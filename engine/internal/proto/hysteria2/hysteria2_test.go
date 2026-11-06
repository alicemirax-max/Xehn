package hysteria2

import (
	"context"
	"testing"

	"tuntrail/internal/config"
)

func profile(h *config.Hysteria2Profile) *config.Profile {
	return &config.Profile{ID: "t", Protocol: config.ProtoHysteria2, Hysteria2: h}
}

func TestNewRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		h    *config.Hysteria2Profile
	}{
		{"nil block", nil},
		{"no server", &config.Hysteria2Profile{Password: "x"}},
		{"no password", &config.Hysteria2Profile{Server: "a.com"}},
	}
	for _, c := range cases {
		if _, err := New(context.Background(), profile(c.h), nil); err == nil {
			t.Errorf("%s: expected an error, got nil", c.name)
		}
	}
}

func TestNewAcceptsMinimalProfile(t *testing.T) {
	d, err := New(context.Background(), profile(&config.Hysteria2Profile{
		Server:   "example.com",
		Password: "secret",
	}), nil)
	if err != nil {
		t.Fatalf("minimal profile rejected: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestDefaultsAreApplied(t *testing.T) {
	// Port 0 must become 443 and zero speeds must become sane defaults
	// rather than triggering Brutal's minimum-rate rejection.
	d, err := New(context.Background(), profile(&config.Hysteria2Profile{
		Server:   "example.com",
		Port:     0,
		Password: "secret",
		UpMbps:   0,
		DownMbps: 0,
	}), nil)
	if err != nil {
		t.Fatalf("defaults failed: %v", err)
	}
	defer d.Close()
}

func TestCloseIsIdempotent(t *testing.T) {
	d, err := New(context.Background(), profile(&config.Hysteria2Profile{
		Server: "example.com", Password: "x",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("second Close returned %v, want nil", err)
	}
}

func TestDialAfterCloseFails(t *testing.T) {
	d, err := New(context.Background(), profile(&config.Hysteria2Profile{
		Server: "example.com", Password: "x",
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if _, err := d.Dial(context.Background(), "tcp", "1.1.1.1:443"); err == nil {
		t.Fatal("Dial on a closed device should fail")
	}
}
