// recce-normalize: canonicalize and de-duplicate a JSON-lines record stream.
//
// A record is a single JSON object per line, e.g.
//   {"kind":"asset","type":"subdomain","value":"A.Example.com.","attrs":{...}}
//   {"kind":"finding","title":"...","severity":"high",...}
//
// For asset records the `value` is canonicalized (trimmed, lowercased for
// host-like types, trailing dot stripped) and duplicates within the stream
// (same kind+type+value) are dropped. Finding records pass through unchanged;
// their de-duplication happens at ingest via dedup_key.
//
// stdlib only — builds with `go build` and no network.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// host-like asset types get lowercased; others keep original case (e.g. urls
// may carry case-sensitive paths, so we only trim them).
var hostLike = map[string]bool{
	"domain":    true,
	"subdomain": true,
	"ip":        true,
	"service":   true,
	"tech":      true,
	"cert":      true,
}

func canonValue(t, v string) string {
	v = strings.TrimSpace(v)
	if hostLike[t] {
		v = strings.ToLower(v)
		v = strings.TrimSuffix(v, ".")
	}
	return v
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	seen := make(map[string]struct{})
	var kept, dropped, bad int

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			bad++
			continue
		}

		kind, _ := rec["kind"].(string)
		if kind == "asset" {
			t, _ := rec["type"].(string)
			v, _ := rec["value"].(string)
			cv := canonValue(t, v)
			if cv == "" {
				bad++
				continue
			}
			rec["value"] = cv
			key := "asset\x00" + t + "\x00" + cv
			if _, dup := seen[key]; dup {
				dropped++
				continue
			}
			seen[key] = struct{}{}
		}

		b, err := json.Marshal(rec)
		if err != nil {
			bad++
			continue
		}
		out.Write(b)
		out.WriteByte('\n')
		out.Flush() // stream: flush each record so the pipeline commits progressively
		kept++
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "recce-normalize: read error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "recce-normalize: kept=%d dropped_dupe=%d bad=%d\n", kept, dropped, bad)
}
