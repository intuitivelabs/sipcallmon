// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

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

	"github.com/intuitivelabs/sipcallmon"
)

import _ "net/http/pprof"

func main() {
	defaultCfg := sipcallmon.GetDefaultCfg()
	cfg, err := sipcallmon.CfgFromOSArgs(&defaultCfg)
	if err != nil {
		fmt.Printf("command line arguments error %s\n", err)
		os.Exit(-1)
	}
	if err = sipcallmon.CfgCheck(&cfg); err != nil {
		fmt.Printf("config  error %s\n", err)
		os.Exit(-1)
	}
	sipcallmon.EventsRing.Init(cfg.EvBufferSz)
	if err = sipcallmon.Init(&cfg); err != nil {
		fmt.Printf("init error %s\n", err)
		os.Exit(-1)
	}
	if err = sipcallmon.Run(&cfg); err != nil {
		fmt.Printf("run failed %s\n", err)
	}
}
