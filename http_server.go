// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

type httpHandler struct {
	url  string
	desc string
	hF   func(w http.ResponseWriter, r *http.Request)
}

var httpInitHandlers = [...]httpHandler{
	{"/about", "", httpPrintVer},
	{"/about/config", "", httpPrintConfig},
	{"/calls", "", httpCallStats},
	{"/calls/list", "", httpCallList},
	{"/calls/list/query", "", httpCallListQuery},
	{"/counters", "", httpPrintCounters},
	{"/debug/options", "", httpDbgOptions},
	{"/debug/pprof", "", nil},
	{"/events", "", httpEventsList},
	{"/events/blst", "", httpEventsBlst},
	{"/events/query", "", httpEventsQuery},
	{"/evrateblst", "", httpEvRateBlstStats},
	{"/evrateblst/list", "", httpEvRateBlstList},
	{"/evrateblst/list/query", "", httpEvRateBlstListQuery},
	{"/evrateblst/rates", "", httpEventsRates},
	{"/evrateblst/forcegc", "", httpEvRateBlstForceGC},
	{"/evrateblst/gccfg1", "", httpEvRateBlstGCcfg1},
	{"/evrateblst/gccfg2", "", httpEvRateBlstGCcfg2},
	{"/inject", "", httpInjectMsg},
	{"/regs", "", httpRegStats},
	{"/regs/list", "", httpRegBindingsList},
	{"/regs/list/query", "", httpRegBindingsListQuery},
	{"/stats", "", httpPrintStats},
	{"/stats/avg", "", httpPrintStatsAvg},
	{"/stats/avg?d=10s", "/stats/avg 10s", httpPrintStatsAvg},
	{"/stats/avg?d=1m", "/stats/avg 1min", httpPrintStatsAvg},
	{"/stats/avg?d=1h", "/stats/avg 1h", httpPrintStatsAvg},
	{"/stats/raw", "", httpPrintStats},
	{"/stats/rate", "", httpPrintStatsRate},
}

var httpHandlers []httpHandler = httpInitHandlers[:]

func init() {
	for _, sr := range statsRate[:] {
		httpHandlers = append(httpHandlers,
			httpHandler{"/stats/rate?d=" + sr.Delta.String(),
				"/stats/rate " + sr.Delta.String(), nil})

	}
}

func HTTPServerRun(laddr string, port int, wg *sync.WaitGroup) error {
	if httpSrv != nil {
		return fmt.Errorf("http server already intialised")
	}
	addr := fmt.Sprintf("%s:%d", laddr, port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %s", addr, err)
	}

	// mux := http.NewServeMux()
	mux := http.DefaultServeMux
	for _, h := range httpHandlers {
		if h.hF != nil {
			mux.HandleFunc(h.url, h.hF)
		}
	}
	mux.HandleFunc("/", httpIndex)
	httpSrv = &http.Server{Addr: addr, Handler: mux}
	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		/* ListenAndServer uses ipv6 by default if ip/host is empty
		err := http.ListenAndServe(addr, nil)
		*/
		err = httpSrv.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			ERR("failed to start web server: %s\n", err)
			os.Exit(-1)
		}
		// httpSrv.Serve() should return only with http.ErrServerClosed
		// (if not Shutdown() or Close() it will run forever)
	}()
	return nil
}

func httpIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, httpHeader)
	for i, h := range httpHandlers {
		txt := h.desc
		if len(txt) == 0 {
			txt = h.url
		}
		fmt.Fprintf(w, "<a href=%q>[%d. %s]</a><br>", h.url, i, txt)
	}
	fmt.Fprintln(w, httpFooter)
}

func httpPrintVer(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s version %s\n", path.Base(os.Args[0]), Version)
	fmt.Fprintf(w, "%s build tags: %v\n", path.Base(os.Args[0]), BuildTags)
	fmt.Fprintf(w, "\ncalltr build tags: %v\n", calltr.BuildTags)
	fmt.Fprintf(w, "calltr alloc type: %v\n", calltr.AllocTypeName)

	if bi, ok := debug.ReadBuildInfo(); ok {
		fmt.Fprintf(w, "\ndeps:\n")
		for _, m := range bi.Deps[:] {
			if m.Replace != nil {
				fmt.Fprintf(w, "    %-40s    v: %-40s",
					m.Replace.Path, m.Replace.Version)
				fmt.Fprintf(w, "  [r: %s]\n",
					m.Path)
			} else {
				fmt.Fprintf(w, "    %-40s    v: %-40s\n",
					m.Path, m.Version)
			}
		}
	}
}

func printStruct(w io.Writer, prefix string, v reflect.Value) {
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		tf := t.Field(i)
		tag := tf.Tag.Get("config")
		if len(tag) == 0 {
			tag = tf.Name
		}
		if tf.Type.Kind() == reflect.Struct {
			printStruct(w, prefix+tag+".", f)
		} else {
			fmt.Fprintf(w, "%s%s: %v\n", prefix, tag, f.Interface())
		}
	}
}

func httpPrintConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s command line arguments: %+v\n\n", os.Args[0], os.Args[1:])
	//	fmt.Fprintf(w, "Config:\n%s\n",
	//		strings.Replace(fmt.Sprintf("%+v", *RunningCfg), " ", "\n", -1))
	fmt.Fprintln(w, "Config:")
	printStruct(w, "	", reflect.ValueOf(RunningCfg).Elem())

}

func httpPrintStats(w http.ResponseWriter, r *http.Request) {
	/*	fmt.Fprintf(w, "<html><head>\n")
		fmt.Fprintf(w, "<title>SIP Parse Statistics</title>\n")
		fmt.Fprintf(w, "<meta http-equiv=\"refresh\" content=\"3\">\n")
		fmt.Fprintf(w, "</head>\n")
		fmt.Fprintf(w, "<body>\n")
	*/
	//fmt.Fprintf(w, "[%s]\n", html.EscapeString(r.URL.Path))
	if r.URL.Path == "/stats/raw" {
		printStatsRaw(w, &stats)
	} else {
		fmt.Fprintf(w, "uptime: %s", time.Now().Sub(StartTS))
		if !StopTS.IsZero() {
			fmt.Fprintf(w, " stopped since %s runtime: %s",
				time.Now().Sub(StopTS), StopTS.Sub(StartTS))
		}
		fmt.Fprintln(w)
		printStats(w, &stats)
	}
	/*
		fmt.Fprintf(w, "</body>\n")
	*/
}

func httpPrintStatsRate(w http.ResponseWriter, r *http.Request) {
	var s *pstats
	var update time.Duration
	delta := time.Second

	paramDelta := r.URL.Query()["d"]
	if len(paramDelta) > 0 && len(paramDelta[0]) > 0 {
		if d, err := time.ParseDuration(paramDelta[0]); err == nil {
			delta = d
		} else {
			fmt.Fprintf(w, "ERROR: invalid delta/interval d=%q (%s)\n",
				paramDelta, err)
			return
		}
	}
	now := time.Now()
	var tmp pstats
	for _, v := range statsRate[:] {
		if v.Delta == delta {
			if !v.updated.IsZero() {
				// if current time less then delta + last updated or
				// packet processing stopped (end of pcap) use last computed
				// rate
				if now.Add(-v.Delta).Before(v.updated) || !StopTS.IsZero() {
					s = &v.rate
					update = now.Sub(v.updated)
				} else {
					// else re-compute rate now
					statsComputeRate(&tmp, &stats, &v.s0,
						now.Sub(v.t0), v.Delta)
					s = &tmp
				}
			} else {
				s = &stats
			}
			break
		}
	}
	fmt.Fprintf(w, "Rate: per %v (last update: %s ago)	Uptime: %s",
		delta, update, time.Now().Sub(StartTS))
	if !StopTS.IsZero() {
		fmt.Fprintf(w, " Stopped since: %s Runtime: %s",
			time.Now().Sub(StopTS), StopTS.Sub(StartTS))
	}
	fmt.Fprintln(w)
	if s != nil {
		printStats(w, s)
	}
}

func httpPrintStatsAvg(w http.ResponseWriter, r *http.Request) {
	delta := time.Second

	paramDelta := r.URL.Query()["d"]
	if len(paramDelta) > 0 && len(paramDelta[0]) > 0 {
		if d, err := time.ParseDuration(paramDelta[0]); err == nil {
			delta = d
		} else {
			fmt.Fprintf(w, "ERROR: invalid delta/interval d=%q (%s)\n",
				paramDelta, err)
			return
		}
	}

	var now time.Time
	if !StopTS.IsZero() {
		now = StopTS
	} else {
		now = time.Now()
	}
	tdiff := now.Sub(StartTS)
	var dst, zero pstats
	if tdiff != 0 {
		statsComputeRate(&dst, &stats, &zero, tdiff, delta)
		fmt.Fprintf(w, "Avg: per %v	Uptime: %s", delta,
			time.Now().Sub(StartTS))
		if !StopTS.IsZero() {
			fmt.Fprintf(w, " Stopped since: %s Runtime: %s",
				time.Now().Sub(StopTS), StopTS.Sub(StartTS))
		}
		fmt.Fprintln(w)
		printStats(w, &dst)
	} else {
		fmt.Fprintf(w, "Error: timer elapsed is too short -"+
			" start: %s, stop: %s\n",
			StartTS, now)
	}
}

// print entries limits and percent used.
// Params: crt entries, crt entries memory use, entries limit,
// entries memory limit.
func printEntriesLimits(w http.ResponseWriter, r *http.Request,
	crt, crtMem, limit, limitMem uint64) {
	fmt.Fprintf(w, "Limits: %d entries", limit)
	if limit != 0 {
		fmt.Fprintf(w, " (%d%% used)", crt*100/limit)
	} else {
		fmt.Fprintf(w, " (unlimited)")
	}
	fmt.Fprintf(w, " %d Kb memory", limitMem/1024)
	if limitMem != 0 {
		fmt.Fprintf(w, " (%d%% used)\n", crtMem*100/limitMem)
	} else {
		fmt.Fprintf(w, " (unlimited)\n")
	}
}

func httpCallStats(w http.ResponseWriter, r *http.Request) {
	var stats calltr.HStats
	calltr.CallEntriesStatsHash(&stats)
	fmt.Fprintf(w, "CallTracking Hash Stats: %+v\n", stats)

	cCfg := calltr.GetCfg()
	limit := cCfg.Mem.MaxCallEntries
	limitMem := cCfg.Mem.MaxCallEntriesMem
	crt := stats.Crt
	crtMem := calltr.CallEntryAllocStats.TotalSize.Get()
	printEntriesLimits(w, r, crt, crtMem, limit, limitMem)

	fmt.Fprintln(w)
	memStats(w, r, &calltr.CallEntryAllocStats)
}

func httpRegStats(w http.ResponseWriter, r *http.Request) {
	var stats calltr.HStats
	calltr.RegEntriesStatsHash(&stats)
	fmt.Fprintf(w, "Reg Bindings Hash Stats: %+v\n", stats)

	cCfg := calltr.GetCfg()
	limit := cCfg.Mem.MaxRegEntries
	limitMem := cCfg.Mem.MaxRegEntriesMem
	crt := stats.Crt
	crtMem := calltr.RegEntryAllocStats.TotalSize.Get()
	printEntriesLimits(w, r, crt, crtMem, limit, limitMem)

	fmt.Fprintln(w)
	memStats(w, r, &calltr.RegEntryAllocStats)
}

func httpEvRateBlstStats(w http.ResponseWriter, r *http.Request) {
	stats := EvRateBlst.Stats()
	fmt.Fprintf(w, "EvRateBlst  Hash Stats: %+v\n", stats)

	gcCfg := EvRateBlst.GetGCcfg()
	limit := gcCfg.MaxEntries
	crt := stats.Crt
	crtMem := calltr.EvRateEntryAllocStats.TotalSize.Get()
	printEntriesLimits(w, r, crt, crtMem, uint64(limit), 0)

	fmt.Fprintln(w)
	memStats(w, r, &calltr.EvRateEntryAllocStats)
}

func memStats(w http.ResponseWriter, r *http.Request, ms *calltr.AllocStats) {
	fmt.Fprintf(w, "Memory Stats:\n"+
		"	TotalSize: %d NewCalls: %d FreeCalls: %d Failures: %d\n",
		atomic.LoadUint64((*uint64)(&ms.TotalSize)),
		atomic.LoadUint64((*uint64)(&ms.NewCalls)),
		atomic.LoadUint64((*uint64)(&ms.FreeCalls)),
		atomic.LoadUint64((*uint64)(&ms.Failures)),
	)
	v := atomic.LoadUint64((*uint64)(&ms.ZeroSize))
	if v != 0 {
		fmt.Fprintf(w, "	%9d allocs (%3d%%)     size: 0!\n",
			v,
			v*100/(calltr.AllocCallsPerEntry*
				atomic.LoadUint64((*uint64)(&ms.NewCalls))))
	}
	for i := 0; i < len(ms.Sizes); i++ {
		v := atomic.LoadUint64((*uint64)(&ms.Sizes[i]))
		if v != 0 {
			if i < (len(ms.Sizes) - 1) {
				fmt.Fprintf(w, "	%9d allocs (%3d%%)     size: %6d -%6d\n",
					v,
					v*100/(calltr.AllocCallsPerEntry*
						atomic.LoadUint64((*uint64)(&ms.NewCalls))),
					i*calltr.AllocRoundTo+1,
					(i+1)*calltr.AllocRoundTo)
			} else {
				fmt.Fprintf(w, "	%9d allocs (%3d%%)     size: >=   %6d\n",
					v, v*100/2*atomic.LoadUint64((*uint64)(&ms.NewCalls)),
					i*calltr.AllocRoundTo+1)
			}
		}
	}
	fmt.Fprintf(w, "\nPools Stats:\n")
	var tHits, tMiss uint64
	for i := 0; i < len(ms.PoolHits); i++ {
		h := atomic.LoadUint64((*uint64)(&ms.PoolHits[i]))
		m := atomic.LoadUint64((*uint64)(&ms.PoolMiss[i]))
		tHits += h
		tMiss += m
		if h != 0 || m != 0 {
			fmt.Fprintf(w, "	%9d / %9d pool hits/miss (%3d%% / %3d%%)"+
				" size: %6d\n",
				h, m, h*100/(h+m), m*100/(h+m),
				(i+1)*calltr.AllocRoundTo)
		}
	}
	if (tHits + tMiss) > 0 {
		fmt.Fprintf(w, "\nPools Total: %9d / %9d hits/miss (%3d%% / %3d%%)\n",
			tHits, tMiss, tHits*100/(tHits+tMiss), tMiss*100/(tHits+tMiss))
	}
}

var htmlCallFilterParams = map[string]int{
	"cid":   calltr.FilterCallID,
	"ftag":  calltr.FilterFromTag,
	"ttag":  calltr.FilterToTag,
	"key":   calltr.FilterCallKey,
	"state": calltr.FilterState,
}

var htmlRegBindingsFilterParams = map[string]int{
	"aor":     calltr.FilterAOR,
	"contact": calltr.FilterContact,
}

func httpCallListQuery(w http.ResponseWriter, r *http.Request) {
	htmlQueryCallFilter(w, htmlCallFilterParams)
}

func httpCallList(w http.ResponseWriter, r *http.Request) {
	n := 100 // default
	s := 0
	tst := ""
	opName := ""
	operand := calltr.FilterNone
	var re *regexp.Regexp

	paramN := r.URL.Query()["n"]
	paramS := r.URL.Query()["s"]
	paramVal := r.URL.Query()["val"]
	paramFilter := r.URL.Query()["filter"]
	// accept operands either directly, e.g.: cid=foo
	// or for forms via filter=cid&val=foo
	for k, v := range htmlCallFilterParams {
		p, found := r.URL.Query()[k]
		if found {
			if len(p) > 0 {
				tst = p[0]
			}
			operand = v
			opName = k
			// we support only one filter operand
			break
		}
	}
	if len(paramFilter) > 0 && len(paramFilter[0]) > 0 && len(opName) == 0 {
		if op, ok := htmlCallFilterParams[paramFilter[0]]; ok {
			operand = op
			opName = paramFilter[0]
		}
	}
	if len(paramVal) > 0 && len(paramVal[0]) > 0 && len(tst) == 0 {
		tst = paramVal[0]
	}
	paramRe, isRe := r.URL.Query()["re"]
	if len(paramN) > 0 && len(paramN[0]) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}
	if len(paramS) > 0 && len(paramS[0]) > 0 {
		if i, err := strconv.Atoi(paramS[0]); err == nil {
			s = i
		} else {
			fmt.Fprintf(w, "Error: s is non-number %q: %s\n", paramS[0], err)
		}
	}
	if len(paramRe) > 0 {
		if i, err := strconv.Atoi(paramRe[0]); err == nil {
			if i > 0 {
				isRe = true
			} else {
				isRe = false
			}
		}
	}
	if isRe && len(tst) > 0 {
		var err error
		re, err = regexp.CompilePOSIX(tst)
		if err != nil {
			fmt.Fprintf(w, "Error bad regexp %q: %s\n", tst, err)
			return
		}
	}
	fmt.Fprintf(w, "Calls List (filter: from %d max %d matches,"+
		" match %s against %q regexp %v):\n",
		s, n, opName, tst, isRe)
	calltr.PrintCallsFilter(w, s, n, operand, []byte(tst), re)
}

func httpRegBindingsListQuery(w http.ResponseWriter, r *http.Request) {
	htmlQueryRegBindingsFilter(w, htmlRegBindingsFilterParams)
}

func httpRegBindingsList(w http.ResponseWriter, r *http.Request) {
	n := 100 // default
	s := 0
	tst := ""
	opName := ""
	operand := calltr.FilterNone
	var re *regexp.Regexp

	paramN := r.URL.Query()["n"]
	paramS := r.URL.Query()["s"]
	paramVal := r.URL.Query()["val"]
	paramFilter := r.URL.Query()["filter"]
	// accept operands either directly, e.g.: cid=foo
	// or for forms via filter=cid&val=foo
	for k, v := range htmlRegBindingsFilterParams {
		p, found := r.URL.Query()[k]
		if found {
			if len(p) > 0 {
				tst = p[0]
			}
			operand = v
			opName = k
			// we support only one filter operand
			break
		}
	}
	if len(paramFilter) > 0 && len(paramFilter[0]) > 0 && len(opName) == 0 {
		if op, ok := htmlRegBindingsFilterParams[paramFilter[0]]; ok {
			operand = op
			opName = paramFilter[0]
		}
	}
	if len(paramVal) > 0 && len(paramVal[0]) > 0 && len(tst) == 0 {
		tst = paramVal[0]
	}
	paramRe, isRe := r.URL.Query()["re"]
	if len(paramN) > 0 && len(paramN[0]) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}
	if len(paramS) > 0 && len(paramS[0]) > 0 {
		if i, err := strconv.Atoi(paramS[0]); err == nil {
			s = i
		} else {
			fmt.Fprintf(w, "Error: s is non-number %q: %s\n", paramS[0], err)
		}
	}
	if len(paramRe) > 0 {
		if i, err := strconv.Atoi(paramRe[0]); err == nil {
			if i > 0 {
				isRe = true
			} else {
				isRe = false
			}
		}
	}
	if isRe && len(tst) > 0 {
		var err error
		re, err = regexp.CompilePOSIX(tst)
		if err != nil {
			fmt.Fprintf(w, "Error bad regexp %q: %s\n", tst, err)
			return
		}
	}
	fmt.Fprintf(w, "Reg Bindings List (filter: from %d max %d matches,"+
		" match %s against %q regexp %v):\n",
		s, n, opName, tst, isRe)
	calltr.PrintRegBindingsFilter(w, s, n, operand, []byte(tst), re)
}

func httpEvRateBlstList(w http.ResponseWriter, r *http.Request) {
	n := 100 // default
	s := 0
	rIdx := -1 // no rate comp. by default
	rVal := 0
	mVal := -1 // match both blacklisted/exceeded and not blacklisted
	var ipnet *net.IPNet
	var re *regexp.Regexp

	tst := ""

	paramN := r.URL.Query()["n"]   // max entries
	paramS := r.URL.Query()["s"]   // start
	paramIP := r.URL.Query()["ip"] // match against
	paramRate := r.URL.Query()["rate"]
	paramRateIdx := r.URL.Query()["ridx"]
	paramRop := r.URL.Query()["rop"]
	paramVal := r.URL.Query()["val"]
	if len(paramIP) > 0 && len(paramIP[0]) > 0 && len(tst) == 0 {
		tst = paramIP[0]
	}
	paramRe, isRe := r.URL.Query()["re"]
	if len(paramN) > 0 && len(paramN[0]) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}
	if len(paramS) > 0 && len(paramS[0]) > 0 {
		if i, err := strconv.Atoi(paramS[0]); err == nil {
			s = i
		} else {
			fmt.Fprintf(w, "Error: s is non-number %q: %s\n", paramS[0], err)
		}
	}
	if len(paramRe) > 0 {
		if i, err := strconv.Atoi(paramRe[0]); err == nil {
			if i > 0 {
				isRe = true
			} else {
				isRe = false
			}
		}
	}
	if len(paramRate) > 0 && len(paramRate[0]) > 0 {
		if i, err := strconv.Atoi(paramRate[0]); err == nil {
			rVal = i
		} else {
			fmt.Fprintf(w, "Error: rate is non-integer %q: %s\n",
				paramRate[0], err)
		}
		if rIdx == -1 {
			rIdx = 0
		}
	}
	if len(paramRop) > 0 && len(paramRop[0]) > 0 {
		switch paramRop[0] {
		case ">=":
			// do nothing
		case "<":
			rVal = -rVal
		default:
			fmt.Fprintf(w, "Error: invalid rop value %q"+
				" (expected &gt= or &lt)\n")
		}
	}
	if len(paramRateIdx) > 0 && len(paramRateIdx[0]) > 0 {
		if i, err := strconv.Atoi(paramRateIdx[0]); err == nil {
			rIdx = i
			if rIdx < 0 || rIdx >= calltr.NEvRates {
				fmt.Fprintf(w, "Error: invalid value for ridx  %q"+
					" (interval 0 %d)\n",
					paramRateIdx[0], calltr.NEvRates-1)
			}
		} else {
			fmt.Fprintf(w, "Error: ridx is non-number %q: %s\n",
				paramRateIdx[0], err)
		}
	}
	if len(paramVal) > 0 && len(paramVal[0]) > 0 {
		if i, err := strconv.Atoi(paramVal[0]); err == nil {
			mVal = i
		} else {
			fmt.Fprintf(w, "Error: val is non-number %q: %s\n",
				paramVal[0], err)
		}
	}
	if len(tst) > 0 {
		if isRe {
			var err error
			re, err = regexp.CompilePOSIX(tst)
			if err != nil {
				fmt.Fprintf(w, "Error bad regexp %q: %s\n", tst, err)
				return
			}
		} else {
			// ! RE, try to convert to IPNet or IP
			var err error
			_, ipnet, err = net.ParseCIDR(tst)
			if err != nil {
				ip := net.ParseIP(tst)
				if ip != nil {
					ipnet = &net.IPNet{ip, net.CIDRMask(len(ip)*8, len(ip)*8)}
				}
			}
		}
	}
	fmt.Fprintf(w, "Event Rate Blacklist (filter: from %d max %d matches,"+
		" match against %q regexp %v ip %v ridx %d rval %d):\n\n",
		s, n, tst, isRe, ipnet != nil, rIdx, rVal)
	fmt.Fprintf(w, "Total:  events: %d, blst %d, failed blst %d\n\n",
		uint64(evrStats.Get(evrCnts.no)),
		uint64(evrStats.Get(evrCnts.blst)),
		uint64(evrStats.Get(evrCnts.trackFail)))

	EvRateBlst.PrintFilter(w, s, n, mVal, rIdx, rVal, ipnet, re)
}

func httpEvRateBlstListQuery(w http.ResponseWriter, r *http.Request) {
	htmlQueryEvRateBlst(w)
}

func httpEvRateBlstForceGC(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	n := 1

	paramN := r.URL.Query()["n"] // target max entries in the hash
	if len(paramN) > 0 && len(paramN[0]) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}

	eLim := now.Add(-2 * time.Second)
	runLim := now.Add(10 * time.Millisecond)
	fmt.Fprintf(w, "running GC, entries %v, target %d life time lim %v"+
		" runtime limit %v ...\n",
		EvRateBlst.CrtEntries(), n,
		eLim.Sub(now), runLim.Sub(now))
	// match non-exceeded (blacklisted entries), which were created (T0)
	// more then 2s in the past (from the current time)
	m := calltr.MatchEvRTS{
		OpEx: calltr.MOpEQ, Ex: false,
		OpT0: calltr.MOpLT, T0: eLim, // T0 < eLim
	}
	ok, entries, to := EvRateBlst.ForceEvict(uint64(n), m, now, runLim)
	fmt.Fprintf(w, "GC run: target %d met: %v (crt %d entries),"+
		" run timeout %v, entries walked: %v\n",
		n, ok, EvRateBlst.CrtEntries(),
		to, entries)
}

// runtime config for event rate blacklist hard & light GC
// (GC done internally when running out of entries)
func httpEvRateBlstGCcfg2(w http.ResponseWriter, r *http.Request) {
	cfg := EvRateBlst.GetGCcfg()
	matchCsz := len(*cfg.ForceGCMatchC)
	if matchCsz < 10 {
		matchCsz = 10 // maximum reasonable no of match conditions for hard gc
	}
	matchC := make([]calltr.MatchEvROffs, len(*cfg.ForceGCMatchC), matchCsz)
	copy(matchC, *cfg.ForceGCMatchC)

	runLsz := len(*cfg.ForceGCrunL)
	if runLsz < 10 {
		runLsz = 10 // maximum reasonable no of hard gc runtime limits
	}
	runL := make([]time.Duration, len(*cfg.ForceGCrunL), runLsz)
	copy(runL, *cfg.ForceGCrunL)

	gcCfg := *cfg
	// deep copy, change array pointer to our copy
	gcCfg.ForceGCMatchC = &matchC
	gcCfg.ForceGCrunL = &runL

	chgs := 0

	s := r.FormValue("max_entries")
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			gcCfg.MaxEntries = uint32(v)
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad max_entries value (%q) : %s\n", s, err)
		}
	}

	s = r.FormValue("hard_gc_target")
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			gcCfg.TargetMax = uint32(v)
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad hard_gc_target value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("light_gc_trigger")
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			gcCfg.GCtrigger = uint32(v)
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad light_gc_trigger value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("light_gc_target")
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			gcCfg.GCtarget = uint32(v)
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad light_gc_target value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("light_gc_lifetime")
	if len(s) > 0 {
		if v, err := time.ParseDuration(s); err == nil {
			gcCfg.LightGCtimeL = v
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad light_gc_lifetime value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("light_gc_max_runtime")
	if len(s) > 0 {
		if v, err := time.ParseDuration(s); err == nil {
			gcCfg.LightGCrunL = v
			chgs++
		} else {
			fmt.Fprintf(w, "ERROR: bad light_gc_max_runtime value (%q) : %s\n",
				s, err)
		}
	}

	// unpack []MatchEvRoffs (match conditions for each hard GC run)
	for i := 0; i < cap(matchC); i++ {
		var m calltr.MatchEvROffs
		if i < len(matchC) {
			m = matchC[i]
		}
		k := 0
		n := "hard_gc_m" + strconv.Itoa(i)
		if s = r.FormValue(n + "_opex"); len(s) > 0 {
			if v, err := calltr.ParseMatchOp(s); err == nil {
				m.OpEx = v
				k++
			}
		}
		if s = r.FormValue(n + "_ex"); len(s) > 0 {
			if v, err := strconv.ParseBool(s); err == nil {
				m.Ex = v
				k++
			}
		}
		if s = r.FormValue(n + "_opt0"); len(s) > 0 {
			if v, err := calltr.ParseMatchOp(s); err == nil {
				m.OpT0 = v
				k++
			}
		}
		if s = r.FormValue(n + "_dt0"); len(s) > 0 {
			if v, err := time.ParseDuration(s); err == nil {
				m.DT0 = v
				k++
			}
		}
		if s = r.FormValue(n + "_opexchgt"); len(s) > 0 {
			if v, err := calltr.ParseMatchOp(s); err == nil {
				m.OpExChgT = v
				k++
			}
		}
		if s = r.FormValue(n + "_dexchgt"); len(s) > 0 {
			if v, err := time.ParseDuration(s); err == nil {
				m.DExChgT = v
				k++
			}
		}
		if s = r.FormValue(n + "_opexlastt"); len(s) > 0 {
			if v, err := calltr.ParseMatchOp(s); err == nil {
				m.OpExLastT = v
				k++
			}
		}
		if s = r.FormValue(n + "_dexlastt"); len(s) > 0 {
			if v, err := time.ParseDuration(s); err == nil {
				m.DExLastT = v
				k++
			}
		}
		if s = r.FormValue(n + "_opoklastt"); len(s) > 0 {
			if v, err := calltr.ParseMatchOp(s); err == nil {
				m.OpOkLastT = v
				k++
			}
		}
		if s = r.FormValue(n + "_doklastt"); len(s) > 0 {
			if v, err := time.ParseDuration(s); err == nil {
				m.DOkLastT = v
				k++
			}
		}
		if k > 0 {
			if i < len(matchC) {
				matchC[i] = m
			} else {
				matchC = append(matchC, m)
			}
		}
	}
	gcCfg.ForceGCMatchC = &matchC // in case it changes (append()...)

	// unpack []time.Duration: ForeGCrunL (for each hard GC run)
	for i := 0; i < cap(runL); i++ {
		n := "rlim" + strconv.Itoa(i)
		if s = r.FormValue(n); len(s) > 0 {
			if v, err := time.ParseDuration(s); err == nil {
				if i < len(runL) {
					runL[i] = v
				} else {
					runL = append(runL, v)
				}
			}
		}
	}
	gcCfg.ForceGCrunL = &runL // in case it changes (append()...)

	htmlEvRateGCparams(w, &gcCfg)
	if chgs > 0 {
		EvRateBlst.SetGCcfg(&gcCfg)
	}
}

// runtime config for event rate periodic GC
// (GC done on timer)
func httpEvRateBlstGCcfg1(w http.ResponseWriter, r *http.Request) {
	cfg := RunningCfg

	s := r.FormValue("evr_gc_interval")
	if len(s) > 0 {
		if v, err := time.ParseDuration(s); err == nil {
			interval := time.Duration(
				atomic.LoadInt64((*int64)(&cfg.EvRgcInterval)))
			if interval != v {
				if atomic.CompareAndSwapInt64(
					(*int64)(&cfg.EvRgcInterval),
					int64(interval), int64(v)) {
					// only if nobody changed the value faster then us
					if !EvRateBlstGCChangeIntvl(v) {
						fmt.Fprintf(w, "ERROR: failed changing"+
							" evr_gc_interval (%q)\n", s)
					}
				}
			}
		} else {
			fmt.Fprintf(w, "ERROR: bad evr_gc_interval value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("evr_gc_old_age")
	if len(s) > 0 {
		if v, err := time.ParseDuration(s); err == nil {
			atomic.StoreInt64((*int64)(&cfg.EvRgcOldAge), int64(v))
		} else {
			fmt.Fprintf(w, "ERROR: bad evr_gc_old_age value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("evr_gc_max_run_time")
	if len(s) > 0 {
		if v, err := time.ParseDuration(s); err == nil {
			atomic.StoreInt64((*int64)(&cfg.EvRgcMaxRunT), int64(v))
		} else {
			fmt.Fprintf(w, "ERROR: bad evr_gc_max_run_time value (%q) : %s\n",
				s, err)
		}
	}

	s = r.FormValue("evr_gc_target")
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 32); err == nil {
			atomic.StoreUint64(&cfg.EvRgcTarget, v)
		} else {
			fmt.Fprintf(w, "ERROR: bad evr_gc_target value (%q) : %s\n",
				s, err)
		}
	}

	htmlEvRatePerGCparams(w, cfg)
}

var ipLocalhost net.IP = net.IP{127, 0, 0, 1}

func httpInjectMsg(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprintln(w, httpHeader, injectForm, httpFooter)
	case "POST":
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "Error ParseForm(): %v", err)
			return
		}
		msgformat := r.FormValue("crlfformat")
		//proto := r.FormValue("proto")
		msg := r.FormValue("sipmsg")
		verbose := false
		verboseStr := r.FormValue("verbose")
		if strings.EqualFold(verboseStr, "yes") {
			verbose = true
		}
		rawmsg, err := unescapeMsg(msg, msgformat)
		if err != nil {
			fmt.Fprintf(w, "Error unescaping message: %v", err)
			return
		}
		fmt.Fprintln(w, httpHeader)
		fmt.Fprintln(w, "<xmp>")
		//fmt.Fprintln(w, "<textarea rows=\"10\" cols=\"120\" readonly>")
		stats.injected++
		stats.seen++
		ok := udpSIPMsg(w, rawmsg, int(stats.injected)-1,
			ipLocalhost, 5060,
			ipLocalhost, 5060, verbose)
		if !verbose {
			fmt.Fprintf(w, "%q\n\n", rawmsg)
		}
		if ok {
			// quick hack to display the injected call (if any)
			var sipmsg sipsp.PSIPMsg
			_, err := sipsp.ParseSIPMsg(rawmsg, 0, &sipmsg,
				sipsp.SIPMsgNoMoreDataF)
			if err == 0 && sipmsg.PV.Callid.Parsed() {
				fmt.Fprintf(w, "filtering callid %q\n", sipmsg.PV.Callid.CallID.Get(sipmsg.Buf))
				calltr.PrintCallsFilter(w, 0, 1000, calltr.FilterCallID,
					sipmsg.PV.Callid.CallID.Get(sipmsg.Buf), nil)
			}
		}
		//fmt.Fprintln(w, "</textarea>")
		fmt.Fprintln(w, "</xmp>")
		fmt.Fprintln(w, injectForm)
		fmt.Fprintln(w, httpFooter)
	default:
		fmt.Fprintf(w, "method %v not supported\n", r.Method)
	}
}

var htmlEvFilterParams = map[string]EvFilterOp{
	"name":    EvFilterName,
	"src":     EvFilterSrc,
	"dst":     EvFilterDst,
	"sport":   EvFilterSport,
	"dport":   EvFilterDport,
	"proto":   EvFilterProto,
	"status":  EvFilterStatus,
	"cid":     EvFilterCallID,
	"fu":      EvFilterFromURI,
	"tu":      EvFilterToURI,
	"method":  EvFilterMethod,
	"uri":     EvFilterRURI,
	"contact": EvFilterContact,
	"reason":  EvFilterReason,
	"ua":      EvFilterUA,
	"uas":     EvFilterUAS,
}

func httpEventsQuery(w http.ResponseWriter, r *http.Request) {
	htmlQueryEvFilter(w, htmlEvFilterParams)
}

func httpEventsList(w http.ResponseWriter, r *http.Request) {
	n := 100 // default
	s := EvRingIdx(0)
	tst := ""
	opName := ""
	operand := EvFilterNone
	var re *regexp.Regexp

	paramN := r.URL.Query()["n"]
	paramS := r.URL.Query()["s"]
	paramVal := r.URL.Query()["val"]
	paramFilter := r.URL.Query()["filter"]
	// accept operands either directly, e.g.: cid=foo
	// or for forms via filter=cid&val=foo
	for k, v := range htmlEvFilterParams {
		p, found := r.URL.Query()[k]
		if found {
			if len(p) > 0 && len(p[0]) > 0 {
				// we support only one filter operand
				tst = p[0]
			}
			// we support only one filter operand
			operand = v
			opName = k
			break
		}
	}
	if len(paramFilter) > 0 && len(paramFilter[0]) > 0 && len(opName) == 0 {
		if op, ok := htmlEvFilterParams[paramFilter[0]]; ok {
			operand = op
			opName = paramFilter[0]
		}
	}
	if len(paramVal) > 0 && len(paramVal[0]) > 0 && len(tst) == 0 {
		tst = paramVal[0]
	}
	paramRe, isRe := r.URL.Query()["re"]
	if len(paramN) > 0 && len(paramN[0]) > 0 {
		if i, err := strconv.Atoi(paramN[0]); err == nil {
			n = i
		} else {
			fmt.Fprintf(w, "Error: n is non-number %q: %s\n", paramN[0], err)
		}
	}
	if len(paramS) > 0 && len(paramS[0]) > 0 {
		if i, err := strconv.Atoi(paramS[0]); err == nil {
			s = EvRingIdx(i)
		} else {
			fmt.Fprintf(w, "Error: s is non-number %q: %s\n", paramS[0], err)
		}
	}
	if len(paramRe) > 0 {
		if i, err := strconv.Atoi(paramRe[0]); err == nil {
			if i > 0 {
				isRe = true
			} else {
				isRe = false
			}
		}
	}
	var substr []byte
	if isRe && len(tst) > 0 {
		var err error
		re, err = regexp.CompilePOSIX(tst)
		if err != nil {
			fmt.Fprintf(w, "Error bad regexp %q: %s\n", tst, err)
			return
		}
	} else {
		substr = []byte(tst)
	}
	fmt.Fprintf(w, "Events List (filter: from %d max %d matches,"+
		" match %s against %q regexp %v):\n",
		s, n, opName, tst, isRe)
	fmt.Fprintf(w, "Total Generated: %6d	Max. Buffered: %6d\n\n",
		EventsRing.idx, len(EventsRing.events))
	// callback arg struct: I don't like closures
	type itParams struct {
		op      EvFilterOp
		substr  []byte
		re      *regexp.Regexp
		printed int
	}
	ItArg := itParams{operand, substr, re, 0}

	ItEvents := func(idx, rel EvRingIdx, ed *calltr.EventData, a interface{}) bool {
		p := a.(*itParams)
		if /*idx >= s && */ matchEvent(ed, p.op, p.substr, p.re) {
			fmt.Fprintf(w, "%5d (%5d). %s\n\n", idx, rel, ed.String())
			p.printed++
			if p.printed >= n {
				return false
			}
		}
		return true
	}

	EventsRing.Iterate(s, ItEvents, &ItArg)
}

func httpEventsBlst(w http.ResponseWriter, r *http.Request) {
	for e := calltr.EvNone + 1; e < calltr.EvBad; e++ {
		param, ok := r.URL.Query()[e.String()]
		set := ok
		if ok && len(param) > 0 && len(param[0]) > 0 {
			if i, err := strconv.Atoi(param[0]); err == nil {
				if i > 0 {
					set = true
				} else {
					set = false
				}
			}
		}
		if set {
			EventsRing.Ignore(e)
		} else if ok {
			EventsRing.UnIgnore(e)
		}
	}
	param, reset := r.URL.Query()["reset"]
	if reset {
		if len(param) > 0 && len(param[0]) > 0 {
			if i, err := strconv.Atoi(param[0]); err == nil {
				if i <= 0 {
					reset = false
				}
			}
		}
		if reset {
			EventsRing.ResetBlst()
		}
	}
	htmlQueryEvBlst(w, EventsRing.evBlst)
}

func httpPrintCounters(w http.ResponseWriter, r *http.Request) {
	groups := r.URL.Query()["group"]
	cntrs := r.URL.Query()["counter"]
	short := false
	s := r.FormValue("short")

	if len(s) > 0 {
		if v, err := strconv.ParseBool(s); err == nil {
			short = v
		} else {
			fmt.Fprintf(w, "ERROR: bad short value (%q) : %s\n", s, err)
		}
	}

	flags := 0
	flgs := r.FormValue("flags")
	if len(flgs) > 0 {
		if v, err := strconv.ParseUint(flgs, 10, 8); err == nil {
			// numeric format
			flags = int(v)
		} else if v, err := strconv.ParseUint(flgs, 16, 8); err == nil {
			// hex format
			flags = int(v)
		} else {
			// string: flags names separated by "|"
			fvals := map[string]int{
				"fullname": counters.PrFullName,
				"val":      counters.PrVal,
				"desc":     counters.PrDesc,
				"rec":      counters.PrRec,
			}
			for _, f := range strings.Split(flgs, "|") {
				if v, ok := fvals[f]; ok {
					flags |= v
				} else {
					fmt.Fprintf(w, "ERROR: unknown flag %s in flags=%q\n",
						f, flgs)
				}
			}
		}
	} else {
		flags = counters.PrFullName | counters.PrVal | counters.PrRec
		if !short {
			flags |= counters.PrDesc
		}
	}

	if len(groups) == 0 && len(cntrs) == 0 {
		// print all counters
		if !short {
			fmt.Fprintf(w, "uptime: %s\n\n", time.Now().Sub(StartTS))
		}
		counters.RootGrp.Print(w, "", flags)
		counters.RootGrp.PrintSubGroups(w, flags)
	}

	if len(groups) != 0 {
		for _, grp := range groups {
			g, errpos := counters.RootGrp.GetSubGroupDot(grp)
			if g != nil {
				g.Print(w, "", flags)
				g.PrintSubGroups(w, flags)
			} else {
				fmt.Fprintf(w, "ERROR: counter group not found after %q: %s\n",
					grp[:errpos], grp[errpos:])
			}
		}
	}
	if len(cntrs) != 0 {
		for _, cnt := range cntrs {
			g, c, errpos := counters.RootGrp.GetCounterDot(cnt)
			if g != nil && c != counters.Invalid {
				g.PrintCounter(w, c, "", "", flags)
			} else {
				if g == nil {
					fmt.Fprintf(w, "ERROR: counter group not"+
						" found after %q: %s\n",
						cnt[:errpos], cnt[errpos:])
				} else {
					fmt.Fprintf(w, "ERROR: counter name not found"+
						" after %q: %s\n",
						cnt[:errpos], cnt[errpos:])
				}
			}
		}
	}
}

func httpDbgOptions(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, httpHeader)

	logChgs := 0

	if v, ok, _ := getIntFormVal(w, r, "log_level", true); ok {
		// set the new log_level everywhere
		atomic.StoreInt64(&RunningCfg.LogLev, v)
		logChgs++
	}
	if v, ok, _ := getUintFormVal(w, r, "log_opt", true); ok {
		// set the new log_level everywhere
		atomic.StoreUint64(&RunningCfg.LogOpt, v)
		logChgs++
	}
	if v, ok, _ := getIntFormVal(w, r, "parse_log_level", true); ok {
		// set the new log_level everywhere
		atomic.StoreInt64(&RunningCfg.ParseLogLev, v)
		logChgs++
	}
	if v, ok, _ := getUintFormVal(w, r, "parse_log_opt", true); ok {
		// set the new log_level everywhere
		atomic.StoreUint64(&RunningCfg.ParseLogOpt, v)
		logChgs++
	}
	if v, ok, _ := getUintFormVal(w, r, "debug_calltr", true); ok {
		// set the new log_level everywhere
		atomic.StoreUint64(&RunningCfg.DbgCalltr, v)
		c := *calltr.GetCfg()
		c.Dbg = calltr.DbgFlags(v)
		calltr.SetCfg(&c)
	}
	if logChgs > 0 {
		// re-init the logs
		initLogs(RunningCfg)
	}

	htmlDbgOptsSetForm(w)
	fmt.Fprintln(w, httpFooter)
}

func httpEventsRates(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, httpHeader)

	errs := 0

	n := "evr_conseq_report_min"
	s := r.FormValue(n)
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			atomic.StoreUint64(&RunningCfg.EvRConseqRmin, v)
		} else {
			fmt.Fprintf(w, "ERROR: bad %s value (%q) : %s\n",
				n, s, err)
		}
	}
	n = "evr_conseq_report_max"
	s = r.FormValue(n)
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			atomic.StoreUint64(&RunningCfg.EvRConseqRmax, v)
		} else {
			fmt.Fprintf(w, "ERROR: bad %s value (%q) : %s\n",
				n, s, err)
		}
	}

	for i := 0; i < calltr.NEvRates; i++ {
		rname := "rate" + strconv.Itoa(i)
		rintvl := "interval" + strconv.Itoa(i)

		param, ok := r.URL.Query()[rname]
		// val >=0 -> set max rate value (== 0 means rate disables)
		// val < 0 -> don't change the current value
		if ok && len(param) > 0 && len(param[0]) > 0 {
			if val, err := strconv.ParseFloat(param[0], 64); err == nil {
				if val >= 0 {
					EvRateBlst.SetRateMax(i, val)
				} // else leave the current value
			} else {
				fmt.Fprintf(w, "ERROR: invalid max value for rate %d:"+
					" %q\n",
					i, param[0])
				errs++
			}
		}
		param, ok = r.URL.Query()[rintvl]
		// val !=0 -> set interval value (== 0 means (here) keep the old value)
		// val < 0 -> don't change the current value
		if ok && len(param) > 0 && len(param[0]) > 0 {
			if d, err := time.ParseDuration(param[0]); err == nil {
				if d != 0 {
					EvRateBlst.SetRateIntvl(i, d)
				} // else if d == 0, leave it untouched
			} else {
				fmt.Fprintf(w, "ERROR: invalid interval for rate %d:"+
					" %q (%s)\n",
					i, param[0], err)
				errs++
			}
		}
	}
	/*
		maxRates := EvRateBlst.GetMaxRates()
		for i, r := range maxRates {
			fmt.Fprintf(w, "rate %d:	%.2f / %v\n", i, r.Max, r.Intvl)
		}
	*/

	if errs > 0 {
		fmt.Fprintln(w, `<br><br><hr><br>`)
	}
	htmlEvRateSetForm(w)
	fmt.Fprintln(w, httpFooter)

}

/*
func httpEventsRatesSet(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, httpHeader)
	htmlEvRateSetForm(w)
	fmt.Fprintln(w, httpFooter)
}
*/

func unescapeMsg(msg string, format string) ([]byte, error) {
	m := []byte(msg)
	f := strings.ToLower(format)
	if f == "auto" {
		for i := 8; i >= 5; i-- {
			if bytes.Count(m, []byte("\\r\\n")) >= i {
				f = "escaped"
				break
			} else if bytes.Count(m, []byte(".\r\n")) >= i {
				f = "ngrepcrlf"
				break
			} else if bytes.Count(m, []byte("\r\n")) >= i {
				f = "crlf"
				break
			} else if bytes.Count(m, []byte(".\n")) >= i {
				f = "ngreplf"
				break
			} else if bytes.Count(m, []byte(".\r")) >= i {
				f = "ngrepcr"
				break
			} else if bytes.Count(m, []byte("\n")) >= i {
				f = "lf"
				break
			} else if bytes.Count(m, []byte("\\n")) >= i {
				if n, err := unescapeMsg(msg, "escaped"); err == nil {
					format = "lf"
					m = n
					break
				} else {
					return nil, err
				}
			}
		}
	}
	switch f {
	case "crlf":
		// do nothing
	case "lf":
		m = bytes.Replace(m, []byte("\n"), []byte("\r\n"), -1)
	case "ngreplf":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\n"), []byte("\r\n"), -1)
	case "ngrepcr":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\r"), []byte("\r\n"), -1)
	case "ngrepcrlf":
		unescapeNgrep(&m)
		//m = bytes.Replace(m, []byte(".\r\n"), []byte("\r\n"), -1)
	case "escaped":
		unescapeBSlice(&m)
	case "auto":
		return nil, fmt.Errorf("could not autodetect format: message" +
			" too short or invalid?")
	default:
		return nil, fmt.Errorf("unknown message format %q", format)
	}
	return m, nil
}

func unescapeNgrep(b *[]byte) {
	buf := *b
	j := 0
	for i := 0; i < len(buf); i++ {
		switch buf[i] {
		case '.':
			if i+2 < len(buf) && buf[i+1] == '\r' && buf[i+2] == '\n' {
				buf[j], buf[j+1] = '\r', '\n'
				j += 2
				i += 2 // skip over next 2 chars
				continue
			} else if i+1 < len(buf) && (buf[i+1] == '\r' || buf[i+1] == '\n') {
				buf[j], buf[j+1] = '\r', '\n'
				j += 2
				i += 1 // skip over next char
				continue
			}
		case '\n', '\r':
			// delete \n or \r not prefixed by '.'
			continue
		}
		buf[j] = buf[i]
		j++
	}
	*b = buf[:j]
}

// in-place !
// expects a string with CRLF escaped. Real CR LF (unescaped) will be
// deleted. Escaped CRLF will be replaced with the real char.
// Same for other standard escapes (\t, \", \hh ...).
func unescapeBSlice(b *[]byte) {
	bs := false
	buf := *b
	j := 0
	for i := 0; i < len(buf); i++ {
		if bs {
			switch buf[i] {
			case 'n':
				buf[j] = '\n'
			case 'r':
				buf[j] = '\r'
			case 'a':
				buf[j] = '\a'
			case 'b':
				buf[j] = '\b'
			case 't':
				buf[j] = '\t'
			case 'v':
				buf[j] = '\v'
			case '\\':
				buf[j] = '\\'
			case '"':
				buf[j] = '"'
			case 'x':
				if i+3 <= len(buf) {
					hex.Decode(buf[j:j+1], buf[i+1:i+3])
					i += 2 // skip over the next 2 chars
				}
			default:
				buf[j] = buf[i]
			}
			j++
			bs = false
		} else if buf[i] == '\\' {
			bs = true
		} else if buf[i] != '\n' && buf[i] != '\r' {
			// skip over real CR or LF
			buf[j] = buf[i]
			j++
		}
	}
	*b = buf[:j]
}
