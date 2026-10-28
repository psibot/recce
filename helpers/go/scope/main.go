// recce-scope: the scope enforcement gate.
//
// Reads a JSON-lines record stream on stdin and passes through only records
// that are in scope, per a rules file (-rules). This runs in the worker on
// every module's output, so a job can never wander outside an engagement's
// boundary — enforcement lives here, not in the UI.
//
// Rules file format:
//   {
//     "include": [ {"type":"domain","value":"example.com"},
//                  {"type":"cidr","value":"10.0.0.0/8"} ],
//     "exclude": [ {"type":"domain","value":"prod.example.com"},
//                  {"type":"regex","value":"^admin\\."} ]
//   }
//
// Matching:
//   domain  - value equals rule, or is a subdomain of it (host endsWith "."+rule)
//   cidr    - record's IP (or resolved host field "ip" in attrs) is within the CIDR
//   regex   - Go regexp against the record value
//
// A record passes if it matches at least one include rule AND matches no
// exclude rule. Finding records pass through (they reference already-scoped
// assets). If no include rules exist, nothing is in scope (fail closed).
//
// stdlib only.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// Asset types that are not addressable hosts and so bypass host-based scope
// matching (they ride along with the in-scope hosts they were derived from).
var nonHostAssetTypes = map[string]bool{
	"tech":       true,
	"waf":        true,
	"email":      true,
	"asn":        true,
	"bucket":     true,
	"screenshot": true,
}

type rule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type rulesFile struct {
	Include []rule `json:"include"`
	Exclude []rule `json:"exclude"`
}

type compiledRule struct {
	kind  string
	raw   string
	cidr  *net.IPNet
	re    *regexp.Regexp
}

func compile(rules []rule) ([]compiledRule, error) {
	var out []compiledRule
	for _, r := range rules {
		cr := compiledRule{kind: r.Type, raw: strings.ToLower(strings.TrimSpace(r.Value))}
		switch r.Type {
		case "cidr":
			_, ipnet, err := net.ParseCIDR(r.Value)
			if err != nil {
				return nil, fmt.Errorf("bad cidr %q: %w", r.Value, err)
			}
			cr.cidr = ipnet
		case "regex":
			re, err := regexp.Compile(r.Value)
			if err != nil {
				return nil, fmt.Errorf("bad regex %q: %w", r.Value, err)
			}
			cr.re = re
		case "domain":
			// nothing to precompile
		default:
			return nil, fmt.Errorf("unknown rule type %q", r.Type)
		}
		out = append(out, cr)
	}
	return out, nil
}

// hostOf extracts the testable host/ip string from an asset record.
func hostOf(rec map[string]interface{}) (host string, ip net.IP) {
	v, _ := rec["value"].(string)
	v = strings.ToLower(strings.TrimSpace(v))
	// url -> strip scheme and path
	if strings.Contains(v, "://") {
		v = v[strings.Index(v, "://")+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	// strip port
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	host = v
	if parsed := net.ParseIP(host); parsed != nil {
		ip = parsed
	}
	// also honor an explicit attrs.ip if present
	if ip == nil {
		if attrs, ok := rec["attrs"].(map[string]interface{}); ok {
			if s, ok := attrs["ip"].(string); ok {
				ip = net.ParseIP(strings.TrimSpace(s))
			}
		}
	}
	return host, ip
}

func matches(cr compiledRule, host string, ip net.IP) bool {
	switch cr.kind {
	case "domain":
		if host == "" {
			return false
		}
		return host == cr.raw || strings.HasSuffix(host, "."+cr.raw)
	case "cidr":
		return ip != nil && cr.cidr.Contains(ip)
	case "regex":
		return cr.re.MatchString(host)
	}
	return false
}

func anyMatch(rules []compiledRule, host string, ip net.IP) bool {
	for _, cr := range rules {
		if matches(cr, host, ip) {
			return true
		}
	}
	return false
}

func main() {
	rulesPath := flag.String("rules", "", "path to JSON scope rules file")
	flag.Parse()
	if *rulesPath == "" {
		fmt.Fprintln(os.Stderr, "recce-scope: -rules is required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recce-scope: cannot read rules: %v\n", err)
		os.Exit(2)
	}
	var rf rulesFile
	if err := json.Unmarshal(raw, &rf); err != nil {
		fmt.Fprintf(os.Stderr, "recce-scope: bad rules json: %v\n", err)
		os.Exit(2)
	}
	includes, err := compile(rf.Include)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recce-scope: %v\n", err)
		os.Exit(2)
	}
	excludes, err := compile(rf.Exclude)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recce-scope: %v\n", err)
		os.Exit(2)
	}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	var passed, blocked int
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		// findings ride along with already-scoped assets
		if kind, _ := rec["kind"].(string); kind == "finding" {
			out.WriteString(line)
			out.WriteByte('\n')
			out.Flush()
			passed++
			continue
		}
		// Non-host asset types aren't addressable hosts — they're properties of
		// or discoveries derived from an already-scoped host (a tech stack, a
		// WAF product, an email, an ASN, a cloud bucket). Host-matching them
		// would wrongly drop them (e.g. value "nginx" matches no domain rule),
		// so they ride along like findings.
		if typ, _ := rec["type"].(string); nonHostAssetTypes[typ] {
			out.WriteString(line)
			out.WriteByte('\n')
			out.Flush()
			passed++
			continue
		}
		host, ip := hostOf(rec)
		if !anyMatch(includes, host, ip) || anyMatch(excludes, host, ip) {
			blocked++
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
		out.Flush()
		passed++
	}
	fmt.Fprintf(os.Stderr, "recce-scope: passed=%d blocked=%d\n", passed, blocked)
}
