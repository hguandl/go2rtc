package marlboze

import (
	"bytes"
	"strings"
	"testing"
)

func TestCrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 16)
	plain := bytes.Repeat([]byte{0x34}, 32)
	encrypted, err := crypt(plain, key, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := crypt(encrypted, key, true)
	if err != nil || !bytes.Equal(plain, decoded) {
		t.Fatal("round trip failed")
	}
	if _, err = crypt([]byte{1}, key, false); err == nil {
		t.Fatal("accepted partial AES block")
	}
	// Exercise login payload construction with invented credentials only.
	key, err = sessionKey("DEMO-123456-TEST", "synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	body, err := loginBody("DEMO-123456-TEST", "synthetic-password", key)
	if err != nil || len(body) != 688 {
		t.Fatal("login payload construction failed")
	}
	encrypted, err = encryptPrefix(body, key, 400)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = crypt(encrypted[:400], key, true)
	if err != nil || !bytes.Equal(append(decoded, encrypted[400:]...), body) {
		t.Fatal("login payload round trip failed")
	}
}

func TestParseURL(t *testing.T) {
	base := "marlboze://DEMO-123456-TEST:p%40ss%3Aword@192.0.2.10?mac="
	for _, mac := range []string{"02-00-00-00-00-01", "02:00:00:00:00:01"} {
		config, err := parseURL(base + mac)
		if err != nil || config.Password != "p@ss:word" || config.Stream != 0 {
			t.Fatal("default stream or userinfo parsing failed")
		}
	}
	config, err := parseURL(base + "02-00-00-00-00-01&stream=1")
	if err != nil || config.Stream != 1 {
		t.Fatal("main stream parsing failed")
	}
	for _, source := range []string{
		"marlboze:",
		base + "invalid",
		base + "02-00-00-00-00-01&stream=2",
		base + "02-00-00-00-00-01&stream=",
		"marlboze://DEMO-123456-TEST:private-value@192.0.2.10/%zz",
	} {
		if _, err := parseURL(source); err == nil || strings.Contains(err.Error(), "private-value") {
			t.Fatal("invalid source accepted or credentials exposed")
		}
	}
}

func TestOrderedChannel(t *testing.T) {
	c := orderedChannel{seq: 65535}
	if err := c.push(0, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if err := c.push(65535, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := c.push(65535, []byte("duplicate")); err != nil {
		t.Fatal(err)
	}
	if string(c.buffer) != "ab" || c.seq != 1 {
		t.Fatal("reorder/wrap failed")
	}
}
