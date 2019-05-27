package main

/* TODO:
          - ip defrag
		  - ip6 defrag ?
		  - tcpreassembly Flush
		  - stream alloc'ed from Pool or special list
		  - options for tcpreassembly mem. limits (pages)
		  - tcp stream re-sync support
		  - option for snap len (live capture)
		   - streams: various optimisations
*/

import (
	"fmt"
	"os"
)

import _ "net/http/pprof"

func main() {
	cfg, err := CfgFromOSArgs(&DefaultConfig)
	if err != nil {
		fmt.Printf("command line arguments error %s\n", err)
		os.Exit(-1)
	}
	Run(&cfg)
}
