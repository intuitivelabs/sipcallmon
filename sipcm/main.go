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

	"andrei/sipcallmon"
)

//import _ "net/http/pprof"

func main() {
	cfg, err := sipcallmon.CfgFromOSArgs(&sipcallmon.DefaultConfig)
	if err != nil {
		fmt.Printf("command line arguments error %s\n", err)
		os.Exit(-1)
	}
	if err = sipcallmon.CfgCheck(&cfg); err != nil {
		fmt.Printf("config  error %s\n", err)
		os.Exit(-1)
	}
	sipcallmon.EventsRing.Init(cfg.EvBufferSz)
	sipcallmon.Run(&cfg)
}
