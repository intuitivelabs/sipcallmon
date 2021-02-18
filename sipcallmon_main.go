// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"math/rand"
	"net/http"
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
var httpSrv *http.Server

// global counters / stats

type evrGCcounters struct {
	runs     counters.Handle
	tgtMet   counters.Handle
	n        counters.Handle
	to       counters.Handle
	gcMticks counters.Handle // missed gc ticks
}

type evrCounters struct {
	no        counters.Handle // total evs
	blst      counters.Handle // blacklist/rate exceeded evs
	trackFail counters.Handle // no rate entry could be created (oom)
	blstSent  counters.Handle // sent blst events
	blstRec   counters.Handle // recovered (previously blacklisted)
}

var evrGCstats *counters.Group
var evrGCcnts evrGCcounters

var evrStats *counters.Group
var evrCnts evrCounters

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
	// stop web server
	if httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "http server shutdown failed: %s\n", err)
			httpSrv.Close() // force Close() just to be sure
		}
	}
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
			evrGCstats.Inc(evrGCcnts.runs)
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
			evrGCstats.Set(evrGCcnts.n, counters.Val(n))
			if tgt {
				evrGCstats.Inc(evrGCcnts.tgtMet)
			}
			if to {
				evrGCstats.Inc(evrGCcnts.to)
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
				evrGCstats.Add(evrGCcnts.gcMticks, counters.Val(missed))
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

// generic function for registering counters, with retries with random
// sufixes in case the counter group with the given name already exists
// and is incompatible.
func registerCounters(name string, grp **counters.Group, defs []counters.Def,
	minEntries, retries int) error {

	grNroot := name
	grName := grNroot
	g := *grp
	entries := minEntries
	if entries < len(defs) {
		entries = len(defs)
	}
	if g == nil {
		g = counters.NewGroup(grName, nil, entries)
	}
	if g == nil {
		// try to register with another name
		for i := 0; i < retries; i++ {
			grName := grNroot + "_" + randStr(4)
			g = counters.NewGroup(grName, nil, entries)
			if g != nil {
				break
			}
		}
		if g == nil {
			return fmt.Errorf("failed to alloc counters group (%q...)\n",
				grName)
		}
	}
	if !g.RegisterDefs(defs) {
		return fmt.Errorf("failed to register  counters (%d to %s)\n",
			len(defs), grName)
	}
	*grp = g
	return nil
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

	// init evr GC counters
	evrGCcntDefs := [...]counters.Def{
		{&evrGCcnts.runs, 0, nil, nil, "gc_runs",
			"periodic GC runs"},
		{&evrGCcnts.tgtMet, 0, nil, nil, "gc_target_met",
			"how many periodic GC runs met their target"},
		{&evrGCcnts.n, counters.CntMaxF | counters.CntMinF, nil, nil,
			"gc_walked",
			"how many entries did the last GC run walk"},
		{&evrGCcnts.to, 0, nil, nil, "gc_timeout",
			"how many periodic GC exited due to timeout"},
		{&evrGCcnts.gcMticks, 0, nil, nil, "gc_missed_ticks",
			"missed ticks, gc is taking too long"},
	}
	// create or reuse counter group "ev_rate_gc" with minimum 100 entries
	// (to leave space for adding more counters, e.g. from other packages
	// like calltr)
	err := registerCounters("ev_rate_gc", &evrGCstats, evrGCcntDefs[:], 100,
		10)
	if err != nil {
		return err
	}

	// init evr generic counters
	evrCntDefs := [...]counters.Def{
		{&evrCnts.no, 0, nil, nil, "total_events",
			"total events seen/processed"},
		{&evrCnts.blst, 0, nil, nil, "total_blst",
			"total events blacklisted"},
		{&evrCnts.blstSent, 0, nil, nil, "blst_sent",
			"sent (generated) blacklisted events"},
		{&evrCnts.trackFail, 0, nil, nil, "tracking_fail",
			"event rate tracking creation failed (exceeded max entries)"},
		{&evrCnts.blstRec, 0, nil, nil, "blst_recovered",
			"recovered, previosuly blacklisted events"},
	}
	err = registerCounters("ev_rate", &evrStats, evrCntDefs[:], 100, 10)
	if err != nil {
		return err
	}

	if EvRateBlst.IsInit() {
		// handle re-init: destroy old and create new
		EvRateBlst.Destroy()
	}
	var maxRates calltr.EvRateMaxes
	calltr.InitEvRateMaxes(&maxRates, &cfg.EvRblstMaxVals, &cfg.EvRblstIntvls)

	// init the event rate blacklist: hash table buckets, max entries.
	EvRateBlst.Init(65535, uint32(cfg.EvRblstMax), &maxRates)

	// init the event ring
	EventsRing.Init(cfg.EvBufferSz)
	for _, t := range cfg.EvTblst {
		if len(t) > 0 {
			if evt, perr := parseEvType(t); perr == nil {
				EventsRing.Ignore(evt)
			} else {
				return fmt.Errorf("invalid event type in even_type_blst: %q",
					t)
			}
		}
	}

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
