package netguard

import (
	"net/netip"
	"testing"
)

func TestModelDialBlockedNAT64Metadata(t *testing.T) {
	pol := ModelPolicy{}
	if !ModelDialBlocked(netip.MustParseAddr("64:ff9b::a9fe:a9fe"), pol) {
		t.Fatal("NAT64 of metadata should be blocked")
	}
	if ModelDialBlocked(netip.MustParseAddr("64:ff9b::5db8:d822"), pol) {
		t.Fatal("NAT64 of public IP should be allowed")
	}
}

func TestNotifyDialBlockedNAT64(t *testing.T) {
	if !NotifyDialBlocked(netip.MustParseAddr("64:ff9b::7f00:1"), false) {
		t.Fatal("NAT64 loopback should be blocked for notify")
	}
	if NotifyDialBlocked(netip.MustParseAddr("10.0.0.5"), false) {
		t.Fatal("RFC1918 should be allowed for notify")
	}
}
