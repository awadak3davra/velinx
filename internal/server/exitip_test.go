package server

import "testing"

func TestParseExitIP(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"203.0.113.7", "203.0.113.7"},
		{"203.0.113.7\n", "203.0.113.7"},
		{"  198.51.100.4  \n", "198.51.100.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"not an ip", ""},
		{"", ""},
		{"<html>error</html>", ""},
		{"203.0.113.7 and more", ""}, // echoes must return a bare IP
	}
	for _, c := range cases {
		if got := parseExitIP(c.in); got != c.want {
			t.Errorf("parseExitIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseIPAPI(t *testing.T) {
	ok := []byte(`{"status":"success","countryCode":"nl","country":"Netherlands","isp":"M247","as":"AS9009 M247 Europe SRL","hosting":true}`)
	g, good := parseIPAPI(ok)
	if !good {
		t.Fatal("expected a successful parse")
	}
	if g.CC != "NL" || g.Country != "Netherlands" || g.ISP != "M247" || g.ASN != "AS9009 M247 Europe SRL" || !g.Hosting {
		t.Errorf("unexpected geo: %+v", g)
	}
	if _, good := parseIPAPI([]byte(`{"status":"fail","message":"private range"}`)); good {
		t.Error("fail status must not parse ok")
	}
	if _, good := parseIPAPI([]byte(`not json`)); good {
		t.Error("garbage must not parse ok")
	}
	if _, good := parseIPAPI([]byte(`{"status":"success"}`)); good {
		t.Error("success with no fields must be treated as empty/not-ok")
	}
}

func TestParseIfconfigGeo(t *testing.T) {
	g, good := parseIfconfigGeo([]byte(`{"country":"United States","country_iso":"us","asn":"AS7922","asn_org":"COMCAST-7922"}`))
	if !good {
		t.Fatal("expected a successful parse")
	}
	if g.CC != "US" || g.Country != "United States" || g.ASN != "AS7922 COMCAST-7922" || g.ISP != "COMCAST-7922" {
		t.Errorf("unexpected geo: %+v", g)
	}
	if g.Hosting {
		t.Error("ifconfig.co has no hosting flag; must default false")
	}
	if _, good := parseIfconfigGeo([]byte(`{}`)); good {
		t.Error("empty object must be not-ok")
	}
}
