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

const Version = "0.7.0"

var RunningCfg *Config

func DBG(f string, a ...interface{}) {
	//	fmt.Printf("DBG: "+f, a...)
}

// ugly temporary hack
var waitgrp *sync.WaitGroup
var stopProcessing = false // if set to 1, will stop
var stopCh chan struct{}
var gcTicker *time.Ticker

// Stop() would signal Run() to exit the processing loop.
func Stop() {
	if stopCh != nil {
		close(stopCh)
	}
	if gcTicker != nil && gcTicker.C != nil {
		gcTicker.Stop()
	}
	stopProcessing = true
	if waitgrp != nil {
		waitgrp.Add(-1)
		waitgrp = nil
	}
}

// evRateBlstLoop runs the ev rate garbage collection periodically
// (based on the passed time.Ticker). It should be run in a separate
// thread.
func evRateBlstGCRun(ticker *time.Ticker, done chan struct{}) {
	defer waitgrp.Done()
	m := calltr.MatchEvRTS{
		OpEx:      calltr.MOpEQ,
		Ex:        false,        // match non exceeded value only
		OpOkLastT: calltr.MOpLT, // match last (time) OK older then ...
		// OkLastT filled each time
	}
	// TODO: make it configurable
	lifetime := 300 * time.Second
	maxRunT := 1 * time.Second
	target := 10 // when to stop GC TODO

	missed := 0
mainloop:
	for {
		select {
		case <-done:
			break mainloop
		case _, ok := <-ticker.C:
			if !ok {
				break mainloop
			}
			now := time.Now()
			m.OkLastT = now.Add(-lifetime)
			runLim := now.Add(maxRunT)
			// run GC
			EvRateBlst.ForceEvict(uint64(target), m, now, runLim)
			// check if another tick passed
			missed = 0
		checkmissed:
			for {
				select {
				case _, ok = <-ticker.C:
					missed++
				default:
					break checkmissed
				}
			}
			if !ok { // ticker.C closed
				break mainloop
			}
			if missed > 0 {
				// GC takes more then 1 tick
				// TODO: do something
			}
		}
	}
}

func evRateBlstStartGC(ticker *time.Ticker, done chan struct{}) {
	waitgrp.Add(1)
	go evRateBlstGCRun(ticker, done)
}

// Run sipcallmon packet processing, based on the passed config.
// It runs in a loop and exits only if Stop() was called, all the
// packet processing ended (pcap reply, EOF and run_forever == false).
func Run(cfg *Config) {
	var maxRates calltr.EvRateMaxes
	// save actual config for global ref.
	RunningCfg = cfg
	// forward config option to calltr
	calltr.Cfg.RegDelta = uint32(cfg.RegDelta)
	calltr.Cfg.ContactIgnorePort = cfg.ContactIgnorePort

	calltr.InitEvRateMaxes(&maxRates, &cfg.EvRblstMaxVals, &cfg.EvRblstIntvls)
	waitgrp = &sync.WaitGroup{}

	// init the event rate blacklist: hash table buckets, max entries.
	EvRateBlst.Init(65535, uint32(cfg.EvRblstMax), &maxRates)
	stopCh = make(chan struct{})
	gcTicker = time.NewTicker(10 * time.Second) // TODO: config
	evRateBlstStartGC(gcTicker, stopCh)

	StartTS = time.Now()

	// ...

	// start web sever
	if cfg.HTTPport != 0 {
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
	} else {
		if stopCh != nil {
			close(stopCh)
		}
	}
}
