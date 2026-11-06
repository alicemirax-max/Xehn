package vless

import (
	"bytes"
	"testing"
)

func TestParseUUID(t *testing.T) {
	u, err := ParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	if err != nil {
		t.Fatalf("ParseUUID: %v", err)
	}
	// b8 31 38 1d 63 24 4d 53 ad 4f 8c da 48 b3 08 11
	want := [16]byte{0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
		0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11}
	if u != want {
		t.Fatalf("got %x, want %x", u, want)
	}
}

func TestParseUUIDRejects(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-uuid",
		"b831381d-6324-4d53-ad4f-8cda48b3081",   // too short
		"b831381d-6324-4d53-ad4f-8cda48b308111", // too long
		"b831381d_6324_4d53_ad4f_8cda48b30811",  // underscores
		"z831381d-6324-4d53-ad4f-8cda48b30811",  // non-hex
	} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("ParseUUID(%q) accepted an invalid uuid", s)
		}
	}
}

func TestBuildHeaderDomain(t *testing.T) {
	uuid, _ := ParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	hdr, err := BuildHeader(Request{
		UUID:    uuid,
		Command: cmdTCP,
		Host:    "example.com",
		Port:    443,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []byte{Version}
	want = append(want, uuid[:]...)
	want = append(want, 0x00, cmdTCP, 0x01, 0xbb) // addonLen, cmd, port hi, port lo
	want = append(want, addrDomain, 0x0b)
	want = append(want, []byte("example.com")...)

	if !bytes.Equal(hdr, want) {
		t.Fatalf("header mismatch\n got %x\nwant %x", hdr, want)
	}
}

func TestBuildHeaderIPv4(t *testing.T) {
	uuid, _ := ParseUUID("00000000-0000-0000-0000-000000000001")
	hdr, err := BuildHeader(Request{UUID: uuid, Command: cmdTCP, Host: "1.2.3.4", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if hdr[len(hdr)-5] != addrIPv4 {
		t.Fatalf("expected IPv4 address type, got %d", hdr[len(hdr)-5])
	}
	if !bytes.Equal(hdr[len(hdr)-4:], []byte{1, 2, 3, 4}) {
		t.Fatalf("wrong address bytes: %x", hdr[len(hdr)-4:])
	}
}

func TestBuildHeaderIPv6(t *testing.T) {
	uuid, _ := ParseUUID("00000000-0000-0000-0000-000000000001")
	hdr, err := BuildHeader(Request{UUID: uuid, Command: cmdTCP, Host: "2001:db8::1", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if hdr[len(hdr)-17] != addrIPv6 {
		t.Fatalf("expected IPv6 address type, got %d", hdr[len(hdr)-17])
	}
}

func TestBuildHeaderRejects(t *testing.T) {
	uuid, _ := ParseUUID("00000000-0000-0000-0000-000000000001")
	if _, err := BuildHeader(Request{UUID: uuid, Command: cmdTCP, Host: "a.com", Port: 0}); err == nil {
		t.Error("port 0 should be rejected")
	}
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := BuildHeader(Request{UUID: uuid, Command: cmdTCP, Host: string(long), Port: 80}); err == nil {
		t.Error("a 256-byte hostname should be rejected")
	}
}
