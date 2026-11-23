// Package netguard classifies outbound dial addresses for the SSRF guards. It
// imports nothing from this module, so every guard (intercept, notify, server)
// can share it.
package netguard

import (
	"net/netip"
)

var (
	// Ranges that are not public Internet addresses and that IsNonPublicAddr
	// does not cover. The shared ones are in use on private networks (overlay
	// networks, fake-IP resolvers), so an allow-listed model endpoint may sit
	// there; the reserved ones are never a model endpoint.
	modelSharedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT (RFC 6598)
		netip.MustParsePrefix("198.18.0.0/15"), // benchmarking (RFC 2544)
	}
	modelReservedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("192.0.0.0/24"), // IETF protocol assignments (RFC 6890)
		netip.MustParsePrefix("240.0.0.0/4"),  // reserved, and the limited broadcast address
	}

	// IPv6 prefixes whose addresses reach the IPv4 host they embed. A DNS64
	// resolver answers with NAT64 addresses for every IPv4-only name, so the
	// prefixes are not blocked as a whole: the embedded address is judged.
	nat64Prefix  = netip.MustParsePrefix("64:ff9b::/96") // the low 32 bits name an IPv4 host
	sixTo4Prefix = netip.MustParsePrefix("2002::/16")    // bits 16 to 47 name an IPv4 host

	// Instance-metadata addresses that lie outside the link-local ranges and
	// would otherwise pass as private or public unicast. 169.254.169.254 is
	// link-local and caught as such.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
		netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	}
)

// ModelPolicy is what the operator has opened up for one model endpoint dial.
type ModelPolicy struct {
	// AllowPrivateEndpoint is set when the endpoint's host:port is listed in
	// ARTEX_LLM_PRIVATE_ENDPOINTS.
	AllowPrivateEndpoint bool
	AllowLoopbackModels  bool
}

// embeddedIPv4 returns the IPv4 address a NAT64 or 6to4 address embeds.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixTo4Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// dialTarget returns the host a dial to addr reaches, seen through the
// IPv4-mapped, NAT64 and 6to4 forms.
func dialTarget(addr netip.Addr) netip.Addr {
	addr = addr.Unmap().WithZone("")
	if v4, ok := embeddedIPv4(addr); ok {
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

// IsMetadata reports whether addr is an instance-metadata address outside the
// link-local ranges.
func IsMetadata(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, m := range metadataAddrs {
		if addr == m {
			return true
		}
	}
	return false
}

// neverExempt reports the addresses no operator setting opens up: loopback,
// unspecified, link-local (169.254.0.0/16 holds 169.254.169.254; fe80::/10),
// multicast and instance metadata.
func neverExempt(addr netip.Addr) bool {
	return addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || IsMetadata(addr)
}

// IsNonPublicAddr reports whether addr is private (RFC1918, fc00::/7 unique
// local) or never exempt (loopback, link-local, unspecified, multicast,
// instance metadata). An invalid address counts as non-public.
func IsNonPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap().WithZone("")
	return addr.IsPrivate() || neverExempt(addr)
}

// ModelDialBlocked reports whether a model endpoint dial to addr must be
// refused. Only public Internet addresses pass unless the policy opens up more.
func ModelDialBlocked(addr netip.Addr, pol ModelPolicy) bool {
	if !addr.IsValid() {
		return true
	}
	addr = dialTarget(addr)
	if pol.AllowLoopbackModels && addr.IsLoopback() {
		return false
	}
	shared := prefixesContain(modelSharedPrefixes, addr)
	if !IsNonPublicAddr(addr) && !shared && !prefixesContain(modelReservedPrefixes, addr) {
		return false
	}
	if pol.AllowPrivateEndpoint {
		// Allow-listed self-hosted endpoints may resolve to loopback, RFC1918 /
		// unique-local private addresses, or the shared ranges above, but never
		// link-local, unspecified, multicast, reserved, or instance-metadata
		// addresses (such as 169.254.169.254, 100.100.100.200 or fd00:ec2::254).
		if addr.IsLoopback() {
			return false
		}
		if (addr.IsPrivate() || shared) && !neverExempt(addr) {
			return false
		}
	}
	return true
}

// NotifyDialBlocked reports whether a notification delivery dial to addr must
// be refused. Loopback, link-local, unspecified, multicast and instance-metadata
// addresses are refused, also behind the IPv4-mapped, NAT64 and 6to4 forms,
// unless allowLocal is set. RFC1918 private networks are allowed: intranet
// relays are common delivery targets.
func NotifyDialBlocked(addr netip.Addr, allowLocal bool) bool {
	if allowLocal {
		return false
	}
	return !addr.IsValid() || neverExempt(dialTarget(addr))
}
