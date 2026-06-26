package config

import "testing"

func TestConfigValidate(t *testing.T) {
	// Default() must always validate — it is the reset/import baseline.
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() config rejected by Validate: %v", err)
	}

	base := func() *Config { return Default() }
	cases := []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"default", func(*Config) {}, true},
		{"empty listen", func(c *Config) { c.Listen = "" }, false},
		{"listen no port", func(c *Config) { c.Listen = "192.168.1.1" }, false},
		{"listen bind-any ok", func(c *Config) { c.Listen = ":8080" }, true},
		{"port out of range", func(c *Config) { c.Ports.UI = 0 }, false},
		{"port too high", func(c *Config) { c.Ports.DNS = 70000 }, false},
		{"duplicate ports", func(c *Config) { c.Ports.Clash = c.Ports.UI }, false},
		{"clash controller bad", func(c *Config) { c.Clash.Controller = "nope" }, false},
		{"clash controller empty ok", func(c *Config) { c.Clash.Controller = "" }, true},
		{"routing mode valid", func(c *Config) { c.RoutingMode = "fast" }, true},
		{"routing mode invalid", func(c *Config) { c.RoutingMode = "turbo" }, false},
		{"offload valid", func(c *Config) { c.Offload = "hw" }, true},
		{"offload invalid", func(c *Config) { c.Offload = "max" }, false},
		{"gateway mtu valid", func(c *Config) { c.GatewayMTU = 1280 }, true},
		{"gateway mtu too low", func(c *Config) { c.GatewayMTU = 100 }, false},
		{"gateway addr valid", func(c *Config) { c.GatewayAddr = "172.19.0.1/30" }, true},
		{"gateway addr invalid", func(c *Config) { c.GatewayAddr = "172.19.0.1" }, false},
		{"webhook http ok", func(c *Config) { c.Watchdog.NotifyURL = "https://hook.test/x" }, true},
		{"webhook not a url", func(c *Config) { c.Watchdog.NotifyURL = "hook.test" }, false},
		{"allowed host ok", func(c *Config) { c.AllowedHosts = []string{"router.lan"} }, true},
		{"allowed host blank", func(c *Config) { c.AllowedHosts = []string{"  "} }, false},
	}
	for _, tc := range cases {
		c := base()
		tc.mut(c)
		err := c.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestPortsValidate(t *testing.T) {
	if err := (Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890}).Validate(); err != nil {
		t.Fatalf("valid ports rejected: %v", err)
	}
	bad := []Ports{
		{UI: 0, Clash: 9090, DNS: 5353, Mixed: 7890},
		{UI: 70000, Clash: 9090, DNS: 5353, Mixed: 7890},
		{UI: 8088, Clash: 8088, DNS: 5353, Mixed: 7890},
		{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 5353},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: invalid ports %+v accepted", i, p)
		}
	}
}

func TestRedacted(t *testing.T) {
	c := Default()
	c.Clash.Secret = "supersecret"
	c.Subscription.Token = "tok123"
	c.Watchdog.NotifyURL = "https://hook.test/abc"
	r := c.Redacted()
	if r.Clash.Secret != RedactedMark || r.Subscription.Token != RedactedMark || r.Watchdog.NotifyURL != RedactedMark {
		t.Fatalf("Redacted left a secret exposed: %+v", r)
	}
	// Original must be untouched (value receiver — operates on a copy).
	if c.Clash.Secret != "supersecret" {
		t.Fatalf("Redacted mutated the original config")
	}
	// Empty secrets stay empty (not masked into a sentinel).
	empty := Default().Redacted()
	if empty.Clash.Secret != "" || empty.Subscription.Token != "" || empty.Watchdog.NotifyURL != "" {
		t.Fatalf("Redacted masked an empty secret: %+v", empty)
	}
}
