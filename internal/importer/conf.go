package importer

import (
	"errors"
	"strings"

	"wakeroute/internal/model"
)

// awgKeys are the AmneziaWG obfuscation parameters whose presence in an [Interface]
// section is how we tell AmneziaWG from plain WireGuard. Jc/Jmin/Jmax/S1/S2/H1-H4
// are 1.x; S3/S4 are 2.0. H1-H4 may be a single value (1.x) or a "min-max" range
// (2.0) — a range is kept as a string. awgKeysHex are the 2.0 I1-I5 hex "magic"
// packets, always stored as strings.
var awgKeys = []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"}
var awgKeysHex = []string{"i1", "i2", "i3", "i4", "i5"}

// parseConf parses a WireGuard / AmneziaWG .conf (INI) into an endpoint.
func parseConf(text string) (*model.Endpoint, error) {
	iface := map[string]string{}
	peer := map[string]string{}
	cur := ""
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}
		switch strings.ToLower(ln) {
		case "[interface]":
			cur = "interface"
			continue
		case "[peer]":
			cur = "peer"
			continue
		}
		eq := strings.IndexByte(ln, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(ln[:eq]))
		val := strings.TrimSpace(ln[eq+1:])
		switch cur {
		case "interface":
			// Address is a REPEATABLE wg-quick key — a dual-stack .conf lists the v4
			// and v6 addresses on separate lines. Accumulate them (comma-join, so the
			// splitCSV below keeps all) instead of overwriting, which silently dropped
			// every address but the last. Other [Interface] keys aren't repeated.
			if key == "address" && iface[key] != "" {
				iface[key] += "," + val
			} else {
				iface[key] = val
			}
		case "peer":
			peer[key] = val
		}
	}

	host, port := splitHostPort(peer["endpoint"])
	if host == "" {
		return nil, errors.New("conf: missing [Peer] Endpoint")
	}
	if port == 0 {
		port = 51820
	}

	isAWG := false
	for _, k := range awgKeys {
		if _, ok := iface[k]; ok {
			isAWG = true
			break
		}
	}

	e := &model.Endpoint{
		Server: host,
		Port:   port,
		Params: map[string]any{
			"private_key":     iface["privatekey"],
			"peer_public_key": peer["publickey"],
		},
	}
	if psk := peer["presharedkey"]; psk != "" {
		e.Params["pre_shared_key"] = psk
	}
	// PersistentKeepalive keeps the NAT/firewall UDP mapping alive on an idle
	// tunnel; dropping it lets the mapping expire so the link silently dies until
	// new traffic forces a re-handshake. The user's awg0/awg1 set it.
	if ka := atoiDefault(peer["persistentkeepalive"], 0); ka > 0 {
		e.Params["persistent_keepalive"] = ka
	}
	if addr := iface["address"]; addr != "" {
		e.Params["local_address"] = splitCSV(addr)
	}
	// WARP's "reserved" client-id bytes (a WARP .conf carries them as a non-standard
	// [Interface] line); only sing-box's plain-WireGuard path uses them, so they are
	// inert for an AmneziaWG .conf but harmless to carry.
	if r := parseReserved(iface["reserved"]); r != nil {
		e.Params["reserved"] = r
	}
	// MTU is an ip-layer [Interface] field that BOTH WG paths need: plain WireGuard
	// emits it on the sing-box endpoint, AmneziaWG applies it on plugin bring-up (it
	// isn't understood by `awg setconf`). Dropping it falls the tunnel back to the
	// kernel default, so large packets fragment/blackhole — e.g. WARP needs MTU 1280.
	if v, ok := iface["mtu"]; ok {
		if n := atoiDefault(v, 0); n > 0 {
			e.Params["mtu"] = n
		}
	}

	if isAWG {
		e.Protocol = model.ProtoAmneziaWG
		e.Engine = model.EngineAmneziaWG
		for _, k := range awgKeys {
			if v, ok := iface[k]; ok {
				// H1-H4 are 32-bit magic values that routinely exceed 2^31; atoiDefault
				// (strconv.Atoi) OVERFLOWS on a 32-bit build (mipsle/mips OpenWrt) and
				// returns 0, zeroing the header so the AWG handshake fails. Keep them as
				// strings (numStr emits them verbatim, no parse) — a "min-max" range (2.0)
				// is already a string. Jc/Jmin/Jmax/S1-S4 are small, so they stay ints.
				if strings.HasPrefix(k, "h") || strings.ContainsRune(v, '-') {
					e.Params[k] = v
				} else {
					e.Params[k] = atoiDefault(v, 0)
				}
			}
		}
		for _, k := range awgKeysHex {
			if v, ok := iface[k]; ok {
				e.Params[k] = v // I1-I5 hex magic
			}
		}
		e.Name = "AmneziaWG " + host
	} else {
		e.Protocol = model.ProtoWireGuard
		e.Engine = model.EngineSingBox
		e.Name = "WireGuard " + host
	}
	return e, nil
}
