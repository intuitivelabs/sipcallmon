// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"github.com/intuitivelabs/calltr"
	"os"
	"strings"
	"sync"
	"time"
)

const Version = "0.6.12"

var RunningCfg *Config

func DBG(f string, a ...interface{}) {
	//	fmt.Printf("DBG: "+f, a...)
}

// ugly temporary hack
var waitgrp *sync.WaitGroup
var stopProcessing = false // if set to 1, will stop

func Stop() {
	stopProcessing = true
	if waitgrp != nil {
		waitgrp.Add(-1)
		waitgrp = nil
	}
}

func Run(cfg *Config) {

	// save actual config for global ref.
	RunningCfg = cfg
	// forward config option to calltr
	calltr.Cfg.RegDelta = uint32(cfg.RegDelta)
	calltr.Cfg.ContactIgnorePort = cfg.ContactIgnorePort

	StartTS = time.Now()

	// ...

	// start web sever
	if cfg.HTTPport != 0 {
		waitgrp = &sync.WaitGroup{}
		if err := HTTPServerRun(cfg.HTTPaddr, cfg.HTTPport, waitgrp); err != nil {
			fmt.Printf("starting web server error: %s\n", err)
			os.Exit(-1)
		}
	}

	if len(cfg.PCAPs) > 0 {
		/*
			for i := 0; i < flag.NArg(); i++ {
				processPCAP(flag.Arg(i), &cfg)
			}
		*/
		for _, fn := range strings.Split(cfg.PCAPs, " ") {
			processPCAP(fn, cfg)
		}
	} else {
		//processLive(cfg.Iface, strings.Join(flag.Args(), " "), &cfg)
		processLive(cfg.Iface, cfg.BPF, cfg)
	}
	StopTS = time.Now()
	// print stats
	printStats(os.Stdout, &stats)
	if cfg.RunForever && !stopProcessing && waitgrp != nil {
		waitgrp.Wait()
	}
}
