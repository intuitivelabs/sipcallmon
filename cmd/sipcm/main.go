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
	"os/signal"
	"syscall"

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
	if err = sipcallmon.Init(&cfg); err != nil {
		fmt.Printf("init error %s\n", err)
		os.Exit(-1)
	}

	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigch)

	done := make(chan struct{}, 1)
	exitCode := 0

	go func() {
		if err = sipcallmon.Run(&cfg); err != nil {
			fmt.Printf("run failed: %s\n", err)
			exitCode = -1
			//os.Exit(-1)
		}
		close(done)
	}()

	// wait till Run() exits or we get a signal

	select {
	case sig := <-sigch:
		switch sig {
		case syscall.SIGINT:
			fallthrough
		case syscall.SIGTERM:
			// terminate immediatly
			go sipcallmon.Stop()
			// in case it did not stop and we receive more
			// signals force-quit
			var i int
		countsigs:
			for i = 0; i < 2; i++ {
				select {
				case <-done:
					break countsigs
				case s := <-sigch:
					if s == syscall.SIGINT || s == syscall.SIGTERM {
						fmt.Fprintf(os.Stderr, "repeated signal (%d/3) : %d\n",
							i+2, s)
					}
				}
			}
			if i == 2 {
				fmt.Fprintf(os.Stderr, "force exit after  %d signals\n", i)
				os.Exit(1)
			}
		}
	case <-done:
		// Run() has finished -> gracefull exit
	}
	os.Exit(exitCode)
}
