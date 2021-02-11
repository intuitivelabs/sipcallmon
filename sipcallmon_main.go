// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
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

// global counters / stats
var evrGCstats *counters.Group
var cntEvRpGCruns counters.Handle
var cntEvRpGCtgtMet counters.Handle
var cntEvRpGCn counters.Handle
var cntEvRpGCto counters.Handle

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

// EvRateBlstGCChangeIntvl changes the interval used for the periodic GC.
func EvRateBlstGCChangeIntvl(intvl time.Duration) bool {
	p := (*unsafe.Pointer)((unsafe.Pointer)(&gcTicker))
	t := (*time.Ticker)(atomic.LoadPointer(p))
	if t != nil {
		if intvl == 0 {
			// disable
			t.Stop()
			return true
		}
		t.Reset(intvl) // should work even if the timer is stopped
	} else {
		// no ticker started
		if intvl == 0 {
			return true
		}
		if stopCh == nil {
			// no stop channel, bail out (called before start or after stop)
			return false
		}
		// not started => start it
		ticker := time.NewTicker(intvl)
		if atomic.CompareAndSwapPointer(p, nil, unsafe.Pointer(ticker)) {
			// success, nobody changed it in parallel
			evRateBlstStartGC(ticker, stopCh)
		} else {
			// parallel change -> give up on our ticker and change the new one
			ticker.Stop()
			t := (*time.Ticker)(atomic.LoadPointer(p))
			t.Reset(intvl)
		}
	}
	return true
}

// evRateBlstLoop runs the ev rate garbage collection periodically
// (based on the passed time.Ticker). It should be run in a separate
// thread.
func evRateBlstGCRun(ticker *time.Ticker, done chan struct{}) {
	// TODO: counters
	defer waitgrp.Done()
	m := calltr.MatchEvRTS{
		OpEx:      calltr.MOpEQ,
		Ex:        false,        // match non exceeded value only
		OpOkLastT: calltr.MOpLT, // match last (time) OK older then ...
		// OkLastT filled each time
	}

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
			evrGCstats.Inc(cntEvRpGCruns)
			lifetime := time.Duration(
				atomic.LoadInt64((*int64)(&RunningCfg.EvRgcOldAge)))
			maxRunT := time.Duration(
				atomic.LoadInt64((*int64)(&RunningCfg.EvRgcMaxRunT)))
			target := atomic.LoadUint64(&RunningCfg.EvRgcTarget)
			now := time.Now()
			m.OkLastT = now.Add(-lifetime)
			runLim := now.Add(maxRunT)
			// run GC
			e0 := EvRateBlst.CrtEntries()
			tgt, n, to := EvRateBlst.ForceEvict(target, m, now, runLim)
			e1 := EvRateBlst.CrtEntries()
			DBG("GC run => target met: %v (%v / %v) n: %v / %v timeout: %v\n", tgt, e1, e0, n, e0, to)
			evrGCstats.Set(cntEvRpGCn, counters.Val(n))
			if tgt {
				evrGCstats.Inc(cntEvRpGCtgtMet)
			}
			if to {
				evrGCstats.Inc(cntEvRpGCto)
			}
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
				DBG("GC run missed ticks: %v\n", time.Now().Sub(now))
			}
		}
	}
}

// returns a random ascii letters string of len n
// (not optimised for speed, intended for init use)
func randStr(n int) string {
	const chSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var b = make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = chSet[rand.Intn(len(chSet))]
	}
	return *(*string)(unsafe.Pointer(&b)) // avoid slice copy + alloc
}

func evRateBlstStartGC(ticker *time.Ticker, done chan struct{}) {
	waitgrp.Add(1)
	go evRateBlstGCRun(ticker, done)
}

// Init pre-initializes sipcallmon.
func Init(cfg *Config) error {

	if cfg == nil {
		return fmt.Errorf("invalid nil config in Init\n")
	}

	// save actual config for global ref.
	RunningCfg = cfg
	// forward config option to calltr
	calltr.Cfg.RegDelta = uint32(cfg.RegDelta)
	calltr.Cfg.ContactIgnorePort = cfg.ContactIgnorePort

	// init counters
	evrCntDefs := [...]counters.Def{
		{&cntEvRpGCruns, 0, nil, nil, "gc_runs",
			"periodic GC runs"},
		{&cntEvRpGCtgtMet, 0, nil, nil, "gc_target_met",
			"how many periodic GC runs met their target"},
		{&cntEvRpGCn, counters.CntMaxF, nil, nil, "gc_walked",
			"how many entries did the last GC run walk"},
		{&cntEvRpGCto, 0, nil, nil, "gc_timeout",
			"how many periodic GC exited due to timeout"},
	}
	grNroot := "event_rate_gc"
	grName := grNroot
	if evrGCstats == nil {
		evrGCstats = counters.NewGroup(grName, nil, len(evrCntDefs))
	}
	if evrGCstats == nil {
		// try to register with another name
		for i := 0; i < 10; i++ {
			grName := grNroot + "_" + randStr(4)
			evrGCstats = counters.NewGroup(grName, nil,
				len(evrCntDefs))
			if evrGCstats != nil {
				break
			}
		}
		if evrGCstats == nil {
			return fmt.Errorf("failed to alloc counters group (%q...)\n",
				grName)
		}
	}
	if !evrGCstats.RegisterDefs(evrCntDefs[:]) {
		return fmt.Errorf("failed to register  counters (%d to %s)\n",
			len(evrCntDefs), grName)
	}

	if EvRateBlst.IsInit() {
		// handle re-init: destroy old and create new
		EvRateBlst.Destroy()
	}
	var maxRates calltr.EvRateMaxes
	calltr.InitEvRateMaxes(&maxRates, &cfg.EvRblstMaxVals, &cfg.EvRblstIntvls)

	// init the event rate blacklist: hash table buckets, max entries.
	EvRateBlst.Init(65535, uint32(cfg.EvRblstMax), &maxRates)

	return nil
}

// Run sipcallmon packet processing, based on the passed config.
// It runs in a loop and exits only if Stop() was called, all the
// packet processing ended (pcap reply, EOF and run_forever == false).
func Run(cfg *Config) error {

	if RunningCfg == nil || cfg != RunningCfg {
		if err := Init(cfg); err != nil {
			return err
		}
	}

	waitgrp = &sync.WaitGroup{}
	stopCh = make(chan struct{})
	if cfg.EvRgcInterval != 0 {
		gcTicker = time.NewTicker(cfg.EvRgcInterval)
		evRateBlstStartGC(gcTicker, stopCh)
	}

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
	return nil
}
