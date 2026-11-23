package netguard

import (
	"net/netip"
	"testing"
)

func TestModelDialBlockedNAT64Metadata(t *testing.T) {
	for _, tc := range []struct {
		addr        string
		pol         ModelPolicy
		wantBlocked bool
	}{
		{"64:ff9b::a9fe:a9fe", ModelPolicy{}, true},
		{"64:ff9b::a9fe:a9fe", ModelPolicy{AllowPrivateEndpoint: true, AllowLoopbackModels: true}, true},
		{"64:ff9b::6464:64c8", ModelPolicy{AllowPrivateEndpoint: true}, true},
		{"::ffff:100.100.100.200", ModelPolicy{AllowPrivateEndpoint: true}, true},
		{"fd00:ec2::254", ModelPolicy{AllowPrivateEndpoint: true}, true},
		{"64:ff9b::5db8:d822", ModelPolicy{}, false},
		{"64:ff9b::7f00:1", ModelPolicy{}, true},
		{"64:ff9b::7f00:1", ModelPolicy{AllowLoopbackModels: true}, false},
		{"::1", ModelPolicy{AllowLoopbackModels: true}, false},
		{"10.0.0.1", ModelPolicy{AllowLoopbackModels: true}, true},
		{"fd00::1", ModelPolicy{AllowPrivateEndpoint: true}, false},
	} {
		if got := ModelDialBlocked(netip.MustParseAddr(tc.addr), tc.pol); got != tc.wantBlocked {
			t.Errorf("ModelDialBlocked(%s, %+v) = %v, want %v", tc.addr, tc.pol, got, tc.wantBlocked)
		}
	}
	if !ModelDialBlocked(netip.Addr{}, ModelPolicy{AllowPrivateEndpoint: true, AllowLoopbackModels: true}) {
		t.Error("an invalid address must be blocked")
	}
}

func TestNotifyDialBlockedNAT64(t *testing.T) {
	for addr, wantBlocked := range map[string]bool{
		"64:ff9b::a9fe:a9fe":     true,
		"2002:6464:64c8::1":      true,
		"::ffff:169.254.169.254": true,
		"fd00:ec2::254":          true,
		"fe80::1%eth0":           true,
		"64:ff9b::7f00:1":        true,
		"10.0.0.5":               false,
		"fd00::1":                false,
		"64:ff9b::a00:5":         false,
	} {
		a := netip.MustParseAddr(addr)
		if got := NotifyDialBlocked(a, false); got != wantBlocked {
			t.Errorf("NotifyDialBlocked(%s, false) = %v, want %v", addr, got, wantBlocked)
		}
		if NotifyDialBlocked(a, true) {
			t.Errorf("NotifyDialBlocked(%s, true) blocked, want every address allowed once opted in", addr)
		}
	}
	if !NotifyDialBlocked(netip.Addr{}, false) {
		t.Error("an invalid address must be blocked")
	}
}
