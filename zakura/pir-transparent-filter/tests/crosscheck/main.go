// Generates BIP 158 filters with btcd's gcs package, independently of the Rust
// implementation under test.
//
// Input (stdin): JSON array of cases, each {"name","block_hash_display","elements":[hex,...]}.
// Output (stdout): JSON array of {"name","filter","filter_hash"} with hex values.
//
// Usage: go run . < cases.json > expected.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type input struct {
	Name             string   `json:"name"`
	BlockHashDisplay string   `json:"block_hash_display"`
	Elements         []string `json:"elements"`
}

type output struct {
	Name       string `json:"name"`
	Filter     string `json:"filter"`
	FilterHash string `json:"filter_hash"`
}

func main() {
	var cases []input
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		fmt.Fprintln(os.Stderr, "decode:", err)
		os.Exit(1)
	}
	results := make([]output, 0, len(cases))
	for _, c := range cases {
		// NewHashFromStr parses display (reversed) order, matching the field name.
		hash, err := chainhash.NewHashFromStr(c.BlockHashDisplay)
		if err != nil {
			fmt.Fprintln(os.Stderr, c.Name, "hash:", err)
			os.Exit(1)
		}
		b := builder.WithKeyHash(hash)
		for _, e := range c.Elements {
			raw, err := hex.DecodeString(e)
			if err != nil {
				fmt.Fprintln(os.Stderr, c.Name, "element:", err)
				os.Exit(1)
			}
			b.AddEntry(raw)
		}
		filter, err := b.Build()
		if err != nil {
			fmt.Fprintln(os.Stderr, c.Name, "build:", err)
			os.Exit(1)
		}
		bytes, err := filter.NBytes()
		if err != nil {
			fmt.Fprintln(os.Stderr, c.Name, "bytes:", err)
			os.Exit(1)
		}
		digest, err := builder.GetFilterHash(filter)
		if err != nil {
			fmt.Fprintln(os.Stderr, c.Name, "hash:", err)
			os.Exit(1)
		}
		results = append(results, output{
			Name:       c.Name,
			Filter:     hex.EncodeToString(bytes),
			FilterHash: hex.EncodeToString(digest[:]),
		})
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}
