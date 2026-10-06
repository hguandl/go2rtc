package marlboze

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/creds"
	"github.com/rs/zerolog"
)

var Log = zerolog.Nop()

type Config struct {
	UID, MAC, Password, IP string
	Stream                 uint32
}

func parseURL(rawURL string) (Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "marlboze" || u.User == nil || u.Port() != "" || u.Path != "" || u.Fragment != "" {
		return Config{}, errors.New("marlboze: invalid source URL")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Config{}, errors.New("marlboze: invalid query")
	}
	password, _ := u.User.Password()
	creds.AddSecret(password)
	config := Config{UID: u.User.Username(), Password: password, IP: u.Hostname(), MAC: query.Get("mac")}
	if query.Has("stream") {
		n, err := strconv.ParseUint(query.Get("stream"), 10, 32)
		if err != nil || n > 1 {
			return Config{}, errors.New("marlboze: stream must be 0 or 1")
		}
		config.Stream = uint32(n)
	}
	return config, config.validate()
}

type Client struct {
	*Conn
	key    []byte
	stream uint32
}
type frame struct {
	video       bool
	kind, stamp uint32
	payload     []byte
}

func (config Config) validate() error {
	if net.ParseIP(config.IP).To4() == nil {
		return errors.New("marlboze: IPv4 address required")
	}
	if _, err := uidToken(config.UID); err != nil {
		return err
	}
	if len(config.UID) > 32 || len(config.Password) == 0 || len(config.Password) > 256 || strings.ContainsRune(config.Password, 0) {
		return errors.New("marlboze: invalid device credentials")
	}
	mac, err := net.ParseMAC(config.MAC)
	if err != nil || len(mac) != 6 {
		return errors.New("marlboze: 6-byte MAC required")
	}
	return nil
}

func NewClient(config Config) (*Client, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	conn, err := dialConn(config, discoveryTimeout)
	if err != nil {
		return nil, err
	}
	c := &Client{Conn: conn, stream: config.Stream}
	started := time.Now()
	if c.key, err = sessionKey(config.UID, config.Password); err == nil {
		err = c.login(config)
	}
	if err != nil {
		Log.Debug().Err(err).Dur("elapsed_ms", time.Since(started)).Msg("[marlboze] login failed")
		_ = conn.Close()
		return nil, err
	}
	Log.Debug().Dur("elapsed_ms", time.Since(started)).Msg("[marlboze] login succeeded")
	return c, nil
}

func (c *Client) login(config Config) error {
	body, err := loginBody(config.UID, config.Password, c.key)
	if err != nil {
		return err
	}
	var sum uint16
	for _, v := range body {
		sum += uint16(v)
	}
	ext := make([]byte, 8)
	ext[0] = 10
	binary.LittleEndian.PutUint16(ext[1:], sum)
	binary.LittleEndian.PutUint32(ext[4:], uint32(time.Now().UnixMilli()))
	encrypted, err := encryptPrefix(body, c.key, 400)
	if err != nil {
		return err
	}
	if err = c.command(0x481b, encrypted, ext); err != nil {
		return err
	}
	return c.waitCommand(0x481b, time.Now().Add(loginTimeout))
}

func (c *Client) checkCommands() (uint32, error) {
	channel := &c.channels[0]
	b := channel.buffer
	if len(b) < 24 {
		return 0, nil
	}
	if binary.LittleEndian.Uint32(b) != 0x99999999 {
		return 0, errors.New("marlboze: invalid control header")
	}
	size := binary.LittleEndian.Uint32(b[4:])
	if size > 1<<20 {
		return 0, errors.New("marlboze: control size exceeded")
	}
	if len(b) < 24+int(size) {
		return 0, nil
	}
	cmd, status := binary.LittleEndian.Uint32(b[8:]), int32(binary.LittleEndian.Uint32(b[12:]))
	channel.buffer = b[24+int(size):]
	if status != 0 {
		return 0, errors.New("marlboze: camera rejected command")
	}
	return cmd, nil
}

func (c *Client) waitCommand(wanted uint32, deadline time.Time) error {
	for {
		cmd, err := c.checkCommands()
		if err != nil {
			return err
		}
		if cmd == wanted {
			return nil
		}
		if cmd != 0 {
			continue
		}
		if err = c.pump(deadline); err != nil {
			return err
		}
	}
}

func (c *Client) StartMedia() error {
	start := make([]byte, 28)
	for i, v := range []uint32{0, c.stream, 0, 5, 256, 2, 10} {
		binary.LittleEndian.PutUint32(start[i*4:], v)
	}
	live := make([]byte, 20)
	for i, v := range []uint32{c.stream, 1, 0, 2, 0} {
		binary.LittleEndian.PutUint32(live[i*4:], v)
	}
	for _, request := range []struct {
		cmd  uint32
		body []byte
	}{{0xf002, start}, {0x1001, live}} {
		body, err := encryptPrefix(request.body, c.key, 16)
		if err != nil {
			return err
		}
		if err = c.command(request.cmd, body, nil); err != nil {
			return err
		}
	}
	return c.command(0x3103, nil, nil)
}

func (c *Client) ReadFrame(deadline time.Time) (*frame, error) {
	for {
		for {
			cmd, err := c.checkCommands()
			if err != nil {
				return nil, err
			}
			if cmd == 0 {
				break
			}
		}
		channel := &c.channels[2]
		b := channel.buffer
		if len(b) >= 16 {
			magic := binary.LittleEndian.Uint32(b)
			if magic != 0x46565848 && magic != 0x43215678 && magic != 0x46415848 {
				return nil, errors.New("marlboze: invalid media header")
			}
			size := binary.LittleEndian.Uint32(b[4:])
			if size > 4<<20 {
				return nil, errors.New("marlboze: media size exceeded")
			}
			if len(b) >= 16+int(size) {
				f := &frame{video: magic == 0x46565848, stamp: binary.LittleEndian.Uint32(b[8:]), kind: binary.LittleEndian.Uint32(b[12:]), payload: bytes.Clone(b[16 : 16+int(size)])}
				channel.buffer = b[16+int(size):]
				if magic == 0x46415848 {
					return nil, errors.New("marlboze: unsupported HXAF audio")
				}
				if !f.video && (f.kind != 0 || len(f.payload) == 0) {
					return nil, errors.New("marlboze: unsupported audio frame")
				}
				if f.video {
					var err error
					f.payload, err = decryptVideo(f.payload, c.key, f.kind)
					if err != nil {
						return nil, err
					}
				}
				return f, nil
			}
		}
		if err := c.pump(deadline); err != nil {
			return nil, err
		}
	}
}

func (c *Client) StopMedia() { _ = c.send(0xf0, nil) }
