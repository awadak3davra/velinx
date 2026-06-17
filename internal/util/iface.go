package util

import (
	"fmt"
	"hash/fnv"
)

// AWGIface is the deterministic Linux interface name for an AmneziaWG endpoint's
// plugin tunnel: short (<=15 chars, kernel limit), stable, and derived from the
// endpoint ID so the generator (which emits bind_interface) and the plugin (which
// runs `ip link add`) agree on exactly one name. fnv, not a crypto hash — this is
// just a name, not a secret.
func AWGIface(id string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return fmt.Sprintf("wr-%08x", h.Sum32()) // "wr-" + 8 hex = 11 chars
}
