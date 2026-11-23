// Package netguard centralizes outbound dial IP classification for SSRF guards.
package netguard

import (
	"net/netip"
)

var (
	modelSharedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("198.18.0.0/15"),
	}
	modelReservedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4Prefix = netip.MustParsePrefix("2002::/16")

	// Known cloud metadata addresses beyond classic link-local AWS.
	awsIMDSv4     = netip.MustParseAddr("169.254.169.254")
	alibabaMetaV4 = netip.MustParseAddr("100.100.100.200")
	awsIMDSv6     = netip.MustParseAddr("fd00:ec2::254")
)

// ModelPolicy parameterizes LLM / model endpoint dial blocking.
type ModelPolicy struct {
	AllowPrivateEndpoint bool
	AllowLoopbackModels  bool
}

// EmbeddedIPv4 returns the IPv4 address a NAT64 or 6to4 address embeds.
func EmbeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixTo4Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

func normalizeAddr(addr netip.Addr) netip.Addr {
	if !addr.IsValid() {
		return addr
	}
	addr = addr.Unmap().WithZone("")
	if v4, ok := EmbeddedIPv4(addr); ok {
		return v4
	}
	return addr
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func knownMetadata(addr netip.Addr) bool {
	return addr == awsIMDSv4 || addr == alibabaMetaV4 || addr == awsIMDSv6
}

// isNonPublicAddr mirrors intercept.IsNonPublicAddr without importing intercept
// (notify → netguard → intercept → db → notify cycle).
func isNonPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsPrivate() {
		return true
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return true
	}
	return knownMetadata(addr)
}

// privateDialAllowed reports whether an allow-listed endpoint may dial this address.
func privateDialAllowed(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	if knownMetadata(addr) {
		return false
	}
	return addr.IsPrivate() || prefixesContain(modelSharedPrefixes, addr)
}

// ModelDialBlocked reports whether a resolved dial address must be refused for
// model/LLM egress (strict public Internet unless allow-listed private).
func ModelDialBlocked(addr netip.Addr, pol ModelPolicy) bool {
	if !addr.IsValid() {
		return true
	}
	addr = normalizeAddr(addr)
	if pol.AllowLoopbackModels && addr.IsLoopback() {
		return false
	}
	shared := prefixesContain(modelSharedPrefixes, addr)
	if !isNonPublicAddr(addr) && !shared && !prefixesContain(modelReservedPrefixes, addr) {
		return false
	}
	if pol.AllowPrivateEndpoint {
		if addr.IsLoopback() {
			return false
		}
		if privateDialAllowed(addr) {
			return false
		}
	}
	return true
}

// NotifyDialBlocked reports whether a delivery dial target is forbidden.
// RFC1918 and most public addresses are allowed; loopback, link-local, metadata,
// and NAT64/6to4 embeddings of those are blocked unless allowLocal is true.
func NotifyDialBlocked(addr netip.Addr, allowLocal bool) bool {
	if allowLocal {
		return false
	}
	if !addr.IsValid() {
		return true
	}
	addr = normalizeAddr(addr)
	if knownMetadata(addr) {
		return true
	}
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast()
}
