package marlboze

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/AlexxIT/go2rtc/pkg/h265"
	"github.com/pion/rtp"
)

type Producer struct {
	core.Connection
	client *Client
	frames []*frame
	stop   sync.Once
}

func Dial(rawURL string) (core.Producer, error) {
	config, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}
	p := &Producer{Connection: core.Connection{ID: core.NewID(), FormatName: "marlboze", Protocol: "udp", RemoteAddr: client.peer.String(), Transport: client}, client: client}
	started := time.Now()
	if err = client.StartMedia(); err == nil {
		err = p.probe()
	}
	if err != nil {
		Log.Debug().Err(err).Dur("elapsed_ms", time.Since(started)).Msg("[marlboze] media startup failed")
		_ = p.Stop()
		return nil, err
	}
	Log.Debug().Dur("elapsed_ms", time.Since(started)).Msg("[marlboze] media ready")
	return p, nil
}

// Validate before using helpers that assume complete, well-formed NAL units.
func videoPayload(f *frame) ([]byte, error) {
	b := annexb.EncodeToAVCC(f.payload)
	for i := 0; i < len(b); {
		if len(b)-i < 4 {
			return nil, errors.New("marlboze: truncated NAL length")
		}
		n := int(binary.BigEndian.Uint32(b[i:]))
		i += 4
		if n < 2 || n > len(b)-i {
			return nil, errors.New("marlboze: invalid NAL length")
		}
		i += n
	}
	if len(b) == 0 {
		return nil, errors.New("marlboze: empty video frame")
	}
	return b, nil
}

func (p *Producer) probe() error {
	deadline := time.Now().Add(probeTimeout)
	var video *core.Codec
	audio := false
	buffered := 0
	for video == nil || !audio {
		f, err := p.client.ReadFrame(deadline)
		if err != nil {
			return err
		}
		if !f.video {
			audio = len(f.payload) > 0
			continue
		}
		if video != nil {
			buffered += len(f.payload)
			if buffered > maxBuffer {
				return errors.New("marlboze: probe buffer exceeded")
			}
			p.frames = append(p.frames, f)
			continue
		}
		if f.kind != 1 {
			continue
		}
		b, err := videoPayload(f)
		if err != nil {
			return err
		}
		var sets uint8
		for i := 0; i < len(b); {
			n := int(binary.BigEndian.Uint32(b[i:]))
			kind := (b[i+4] >> 1) & 63
			if kind >= 32 && kind <= 34 {
				sets |= 1 << (kind - 32)
			}
			i += 4 + n
		}
		if sets != 7 {
			continue
		}
		video = h265.AVCCToCodec(b)
		p.frames = append(p.frames, f)
		buffered = len(f.payload)
	}
	p.Medias = []*core.Media{
		{Kind: core.KindVideo, Direction: core.DirectionRecvonly, Codecs: []*core.Codec{video}},
		{Kind: core.KindAudio, Direction: core.DirectionRecvonly, Codecs: []*core.Codec{{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1, PayloadType: 8}}},
	}
	return nil
}

func (p *Producer) Start() error {
	var videoSeq, audioSeq uint16
	frames := p.frames
	p.frames = nil
	for {
		var f *frame
		if len(frames) > 0 {
			f = frames[0]
			frames[0] = nil
			frames = frames[1:]
		}
		if f == nil {
			var err error
			f, err = p.client.ReadFrame(time.Now().Add(frameTimeout))
			if err != nil {
				return err
			}
		}
		p.Recv += len(f.payload)
		name := core.CodecPCMA
		packet := &core.Packet{Header: rtp.Header{Version: 2, Marker: true, PayloadType: 8, SequenceNumber: audioSeq, Timestamp: f.stamp * 8}, Payload: f.payload}
		if f.video {
			name = core.CodecH265
			b, err := videoPayload(f)
			if err != nil {
				return err
			}
			packet.Header.PayloadType = core.PayloadTypeRAW
			packet.Version = h264.RTPPacketVersionAVC
			packet.SequenceNumber = videoSeq
			packet.Timestamp = f.stamp * 90
			packet.Payload = b
			videoSeq++
		} else {
			audioSeq++
		}
		for _, receiver := range p.Receivers {
			if receiver.Codec.Name == name {
				receiver.WriteRTP(packet)
				break
			}
		}
	}
}

func (p *Producer) Stop() error {
	var err error
	p.stop.Do(func() { p.client.StopMedia(); err = p.Connection.Stop() })
	return err
}
