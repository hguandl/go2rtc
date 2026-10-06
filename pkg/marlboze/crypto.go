package marlboze

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// crypt implements the device's AES-ECB wrapper, with XOR before encryption
// and after decryption. Input is block-aligned; there is no PKCS7 padding.
func crypt(data, key []byte, decrypt bool) ([]byte, error) {
	if len(key) != 16 || len(data)%16 != 0 {
		return nil, errors.New("marlboze: invalid AES input")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := bytes.Clone(data)
	for i := 0; i < len(out); i += 16 {
		if decrypt {
			block.Decrypt(out[i:i+16], out[i:i+16])
		}
		for j := i; j < i+16; j++ {
			out[j] ^= 0x3f
		}
		if !decrypt {
			block.Encrypt(out[i:i+16], out[i:i+16])
		}
	}
	return out, nil
}

func padded(value string, size int) []byte {
	out := bytes.Repeat([]byte{'0'}, size)
	copy(out, value)
	return out
}

func sessionKey(uid, password string) ([]byte, error) {
	key := make([]byte, 16)
	copy(key, "hichip2105")
	out, err := crypt(padded(uid+password, 32), key, false)
	if err != nil {
		return nil, err
	}
	return out[:16], nil
}

// A fresh 32-byte login context: transformed microseconds, random bytes in
// [0,160], and an inserted high-bit marker, matching the recovered generator.
func loginContext() ([]byte, error) {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, uint32(time.Now().Nanosecond()/1000))
	for i := 0; i < 4; i++ {
		if b[i] >= 161 {
			b[i] += 95
		}
	}
	for i := 4; i < len(b); i++ {
		var r [1]byte
		for {
			if _, err := rand.Read(r[:]); err != nil {
				return nil, err
			}
			if r[0] < 161 {
				b[i] = r[0]
				break
			}
		}
	}
	var r [1]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	index := int(r[0] & 31)
	for i, v := range b {
		if v >= 128 {
			index = i
			break
		}
	}
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	b[index] = (r[0] & 31) ^ 0x80
	return b, nil
}

func loginBody(uid, password string, key []byte) ([]byte, error) {
	// Alternating encrypted-input and context runs (320 bytes per field).
	layouts := [][]int{
		{14, 4, 12, 5, 35, 7, 33, 3, 85, 1, 57, 8, 16, 4, 36},
		{22, 4, 6, 5, 38, 7, 39, 3, 75, 1, 40, 8, 13, 4, 55},
	}
	body := make([]byte, 688)
	for field, value := range []string{"admin", password} {
		input, err := crypt(append(padded(value, 256), padded(uid, 32)...), key, false)
		if err != nil {
			return nil, err
		}
		context, err := loginContext()
		if err != nil {
			return nil, err
		}
		dest, src, ctx := 4+342*field, 0, 0
		for run, n := range layouts[field] {
			if run%2 == 0 {
				copy(body[dest:], input[src:src+n])
				src += n
			} else {
				copy(body[dest:], context[ctx:ctx+n])
				ctx += n
			}
			dest += n
		}
	}
	return body, nil
}

func encryptPrefix(body, key []byte, n int) ([]byte, error) {
	prefix, err := crypt(body[:n], key, false)
	if err != nil {
		return nil, err
	}
	return append(prefix, body[n:]...), nil
}

func decryptVideo(data, key []byte, kind uint32) ([]byte, error) {
	if kind == 1 && !bytes.HasPrefix(data, []byte{0, 0, 0, 1}) {
		if len(data) < 96 {
			return nil, errors.New("marlboze: truncated keyframe")
		}
		prefix, err := crypt(data[:96], key, true)
		if err != nil {
			return nil, err
		}
		data = append(prefix, data[96:]...)
	}
	if !bytes.HasPrefix(data, []byte{0, 0, 0, 1}) && !bytes.HasPrefix(data, []byte{0, 0, 1}) {
		return nil, errors.New("marlboze: invalid video start code")
	}
	return data, nil
}
