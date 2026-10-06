package marlboze

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxBuffer         = 8 << 20
	discoveryTimeout  = 15 * time.Second
	discoveryInterval = 500 * time.Millisecond
	wakeInterval      = 250 * time.Millisecond
	loginTimeout      = 5 * time.Second
	probeTimeout      = 15 * time.Second
	frameTimeout      = 10 * time.Second
	gapTimeout        = 3 * time.Second
	commandInterval   = time.Second
	commandAttempts   = 4
)

type orderedChannel struct {
	seq     uint16
	pending map[uint16][]byte
	queued  int
	buffer  []byte
	gap     time.Time
}

func (c *orderedChannel) push(seq uint16, data []byte) error {
	distance := uint16(seq - c.seq)
	if distance >= 0x8000 {
		return nil
	}
	if distance > 2048 {
		return errors.New("marlboze: receive window exceeded")
	}
	if c.pending == nil {
		c.pending = make(map[uint16][]byte)
	}
	if _, exists := c.pending[seq]; !exists {
		if len(c.buffer)+c.queued+len(data) > maxBuffer {
			return errors.New("marlboze: receive buffer exceeded")
		}
		c.pending[seq] = bytes.Clone(data)
		c.queued += len(data)
	}
	for {
		data, ok := c.pending[c.seq]
		if !ok {
			break
		}
		if len(c.buffer)+len(data) > maxBuffer {
			return errors.New("marlboze: receive buffer exceeded")
		}
		c.buffer = append(c.buffer, data...)
		c.queued -= len(data)
		delete(c.pending, c.seq)
		c.seq++
	}
	if len(c.pending) == 0 {
		c.gap = time.Time{}
	} else if c.gap.IsZero() {
		c.gap = time.Now()
	}
	return nil
}

type pendingCommand struct {
	packet []byte
	sent   time.Time
	tries  int
}

type Conn struct {
	*net.UDPConn
	peer     *net.UDPAddr
	channels [3]orderedChannel
	pending  map[uint16]*pendingCommand
	seq      uint16
}

func uidToken(uid string) ([]byte, error) {
	parts := strings.Split(uid, "-")
	if len(parts) != 3 || len(parts[0]) == 0 || len(parts[2]) == 0 || len(parts[0]) > 8 || len(parts[2]) > 8 {
		return nil, errors.New("marlboze: invalid UID")
	}
	for _, part := range []string{parts[0], parts[2]} {
		for _, b := range []byte(part) {
			if b < 0x21 || b > 0x7e {
				return nil, errors.New("marlboze: UID must be ASCII")
			}
		}
	}
	n, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, errors.New("marlboze: invalid UID number")
	}
	b := make([]byte, 20)
	copy(b, parts[0])
	binary.BigEndian.PutUint32(b[8:], uint32(n))
	copy(b[12:], parts[2])
	return b, nil
}

func localIP(ip net.IP) (net.IP, error) {
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 32108})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return bytes.Clone(c.LocalAddr().(*net.UDPAddr).IP), nil
}

func dialConn(config Config, timeout time.Duration) (*Conn, error) {
	ip := net.ParseIP(config.IP).To4()
	bind, err := localIP(ip)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: bind})
	if err != nil {
		return nil, err
	}
	c := &Conn{UDPConn: udp, peer: &net.UDPAddr{IP: ip, Port: 32108}, pending: make(map[uint16]*pendingCommand)}
	token, _ := uidToken(config.UID)
	started := time.Now()
	deadline := started.Add(timeout)
	nextWake, nextDiscovery := started, started
	wakeConn, wakePacket, wakeErr := newWakeConn(config, bind)
	if wakeErr != nil {
		Log.Debug().Err(wakeErr).Msg("[marlboze] wake unavailable")
	} else {
		defer wakeConn.Close()
	}
	Log.Debug().Str("bind", bind.String()).Str("ip", ip.String()).Dur("timeout_ms", timeout).Msg("[marlboze] discovery started")
	var requests, sendErrors, received, wrongIP, malformed, wrongUID, wrongKind, wakePackets, wakeErrors int
	defer func() {
		Log.Debug().Dur("elapsed_ms", time.Since(started)).Int("requests", requests).Int("send_errors", sendErrors).
			Int("received", received).Int("wrong_ip", wrongIP).Int("malformed", malformed).
			Int("wrong_uid", wrongUID).Int("wrong_kind", wrongKind).Int("wake_packets", wakePackets).Int("wake_errors", wakeErrors).Msg("[marlboze] discovery summary")
	}()
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		now := time.Now()
		if wakeConn != nil && !now.Before(nextWake) {
			wakePackets++
			if _, err := wakeConn.Write(wakePacket); err != nil {
				wakeErrors++
				if wakeErrors == 1 {
					Log.Debug().Err(err).Msg("[marlboze] wake send failed")
				}
			}
			nextWake = now.Add(wakeInterval)
		}
		if !now.Before(nextDiscovery) {
			requests++
			if err := c.send(0x30, nil); err != nil {
				sendErrors++
				if sendErrors == 1 {
					Log.Debug().Err(err).Msg("[marlboze] discovery send failed")
				}
			}
			nextDiscovery = now.Add(discoveryInterval)
		}
		until := nextDiscovery
		if wakeConn != nil && nextWake.Before(until) {
			until = nextWake
		}
		if until.After(deadline) {
			until = deadline
		}
		_ = c.SetReadDeadline(until)
		for {
			n, peer, err := udp.ReadFromUDP(buf)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					break
				}
				_ = udp.Close()
				return nil, err
			}
			received++
			if !peer.IP.Equal(ip) {
				wrongIP++
				continue
			}
			if n != 24 || buf[0] != 0xf1 || binary.BigEndian.Uint16(buf[2:]) != 20 {
				malformed++
				continue
			}
			if !bytes.Equal(buf[4:n], token) {
				wrongUID++
				continue
			}
			if buf[1] != 0x41 && buf[1] != 0x42 {
				wrongKind++
				continue
			}
			c.peer = peer
			if buf[1] == 0x41 {
				if err := c.send(0x42, token); err != nil {
					_ = udp.Close()
					return nil, err
				}
			}
			_ = c.SetReadDeadline(time.Time{})
			Log.Debug().Int("port", peer.Port).Msg("[marlboze] discovery succeeded")
			return c, nil
		}
	}
	_ = udp.Close()
	return nil, errors.New("marlboze: camera discovery timed out")
}

func (c *Conn) send(kind byte, data []byte) error {
	b := make([]byte, 4+len(data))
	b[0] = 0xf1
	b[1] = kind
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	copy(b[4:], data)
	_, err := c.WriteToUDP(b, c.peer)
	return err
}

func (c *Conn) command(cmd uint32, body, ext []byte) error {
	b := make([]byte, 28+len(body))
	b[0] = 0xd1
	binary.BigEndian.PutUint16(b[2:], c.seq)
	binary.LittleEndian.PutUint32(b[4:], 0x99999999)
	binary.LittleEndian.PutUint32(b[8:], uint32(len(body)))
	binary.LittleEndian.PutUint32(b[12:], cmd)
	copy(b[20:28], ext)
	copy(b[28:], body)
	if err := c.send(0xd0, b); err != nil {
		return err
	}
	c.pending[c.seq] = &pendingCommand{packet: b, sent: time.Now(), tries: 1}
	c.seq++
	return nil
}

// pump is the sole reader and owner of ACK/reorder state.
func (c *Conn) pump(deadline time.Time) error {
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		now := time.Now()
		for _, channel := range c.channels {
			if !channel.gap.IsZero() && now.Sub(channel.gap) > gapTimeout {
				return errors.New("marlboze: unrecovered packet gap")
			}
		}
		for _, p := range c.pending {
			if now.Sub(p.sent) < commandInterval {
				continue
			}
			if p.tries >= commandAttempts {
				return errors.New("marlboze: command ACK timed out")
			}
			if err := c.send(0xd0, p.packet); err != nil {
				return err
			}
			p.sent = now
			p.tries++
		}
		until := now.Add(100 * time.Millisecond)
		if deadline.Before(until) {
			until = deadline
		}
		_ = c.SetReadDeadline(until)
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				continue
			}
			return err
		}
		if !peer.IP.Equal(c.peer.IP) || peer.Port != c.peer.Port || n < 4 || buf[0] != 0xf1 || int(binary.BigEndian.Uint16(buf[2:])) != n-4 {
			continue
		}
		b := buf[4:n]
		switch buf[1] {
		case 0xe0:
			if err := c.send(0xe1, nil); err != nil {
				return err
			}
		case 0xf0:
			return errors.New("marlboze: camera closed session")
		case 0xd1:
			if len(b) < 4 || b[0] != 0xd1 || b[1] != 0 || len(b) != 4+2*int(binary.BigEndian.Uint16(b[2:])) {
				continue
			}
			for i := 4; i < len(b); i += 2 {
				delete(c.pending, binary.BigEndian.Uint16(b[i:]))
			}
		case 0xd0:
			if len(b) < 4 || b[0] != 0xd1 {
				continue
			}
			ch := b[1]
			if ch != 0 && ch != 2 {
				continue
			}
			seq := binary.BigEndian.Uint16(b[2:])
			if err := c.channels[ch].push(seq, b[4:]); err != nil {
				return err
			}
			ack := []byte{0xd1, ch, 0, 1, b[2], b[3]}
			if err := c.send(0xd1, ack); err != nil {
				return err
			}
			return nil
		}
	}
	return errors.New("marlboze: read timed out")
}

// newWakeConn prepares a reusable LAN broadcast socket and MAC wake packet.
func newWakeConn(config Config, bind net.IP) (*net.UDPConn, []byte, error) {
	mac, err := net.ParseMAC(config.MAC)
	if err != nil || len(mac) != 6 {
		return nil, nil, errors.New("marlboze: invalid MAC")
	}
	ip := net.ParseIP(config.IP).To4()
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	var broadcast net.IP
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			netaddr, ok := addr.(*net.IPNet)
			if !ok || !netaddr.IP.Equal(bind) || !netaddr.Contains(ip) {
				continue
			}
			v4 := netaddr.IP.To4()
			if v4 == nil || len(netaddr.Mask) != 4 {
				continue
			}
			broadcast = make(net.IP, 4)
			for i := range broadcast {
				broadcast[i] = v4[i] | ^netaddr.Mask[i]
			}
		}
	}
	if broadcast == nil {
		return nil, nil, errors.New("marlboze: no matching LAN for wake")
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: bind}, &net.UDPAddr{IP: broadcast, Port: 50000})
	if err != nil {
		return nil, nil, err
	}
	b := append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(mac, 16)...)
	b = append(b, make([]byte, 14)...)
	return conn, b, nil
}
