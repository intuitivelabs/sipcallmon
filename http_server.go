package sipcallmon

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"andrei/counters"
	"andrei/sipsp"
	"andrei/sipsp/calltr"
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
	{"/debug/pprof", "", nil},
	{"/events", "", httpEventsList},
	{"/events/blst", "", httpEventsBlst},
	{"/events/query", "", httpEventsQuery},
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
	for _, h := range httpHandlers {
		if h.hF != nil {
			http.HandleFunc(h.url, h.hF)
		}
	}
	http.HandleFunc("/", httpIndex)
	addr := fmt.Sprintf("%s:%d", laddr, port)
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %s\n", addr, err)
	}
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
		err = http.Serve(listener, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to start web server: %s\n",
				err)
			os.Exit(-1)
		}
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
	fmt.Fprintf(w, "%s version %s\n", path.Base(os.Args[0]), version)
}

func httpPrintConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s command line arguments: %+v\n\n", os.Args[0], os.Args[1:])
	fmt.Fprintf(w, "Config:\n%s\n",

		strings.Replace(fmt.Sprintf("%+v", *RunningCfg), " ", "\n", -1))

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
		fmt.Fprintf(w, "uptime: %s\n", time.Now().Sub(StartTS))
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
				if now.Add(-v.Delta).Before(v.updated) {
					s = &v.rate
					update = now.Sub(v.updated)
				} else {
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
	fmt.Fprintf(w, "Rate: per %v (last update: %s ago)	Uptime: %s\n",
		delta, update, time.Now().Sub(StartTS))
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
	now := time.Now()
	var dst, zero pstats
	statsComputeRate(&dst, &stats, &zero, now.Sub(StartTS), delta)
	fmt.Fprintf(w, "Avg: per %v	Uptime: %s\n", delta, time.Now().Sub(StartTS))
	printStats(w, &dst)
}

func httpCallStats(w http.ResponseWriter, r *http.Request) {
	var stats calltr.HStats
	calltr.CallEntriesStatsHash(&stats)
	fmt.Fprintf(w, "CallTracking Hash Stats: %+v\n", stats)
	memStats(w, r, &calltr.CallEntryAllocStats)
}

func httpRegStats(w http.ResponseWriter, r *http.Request) {
	var stats calltr.HStats
	calltr.RegEntriesStatsHash(&stats)
	fmt.Fprintf(w, "Reg Bindings Hash Stats: %+v\n", stats)
	memStats(w, r, &calltr.RegEntryAllocStats)
}

func memStats(w http.ResponseWriter, r *http.Request, ms *calltr.AllocStats) {
	fmt.Fprintf(w, "Memory Stats:\n"+
		"	TotalSize: %d NewCalls: %d FreeCalls: %d Failures: %d\n",
		atomic.LoadUint64((*uint64)(&ms.TotalSize)),
		atomic.LoadUint64((*uint64)(&ms.NewCalls)),
		atomic.LoadUint64((*uint64)(&ms.FreeCalls)),
		atomic.LoadUint64((*uint64)(&ms.Failures)),
	)
	for i := 0; i < len(ms.Sizes); i++ {
		v := atomic.LoadUint64((*uint64)(&ms.Sizes[i]))
		if v != 0 {
			if i < (len(ms.Sizes) - 1) {
				fmt.Fprintf(w, "	%9d allocs (%3d%%)     size: %6d -%6d\n",
					v,
					v*100/(calltr.AllocCallsPerEntry*
						atomic.LoadUint64((*uint64)(&ms.NewCalls))),
					i*calltr.AllocRoundTo,
					(i+1)*calltr.AllocRoundTo-1)
			} else {
				fmt.Fprintf(w, "	%9d allocs (%3d%%)     size: > %6d\n",
					v, v*100/2*atomic.LoadUint64((*uint64)(&ms.NewCalls)),
					i*calltr.AllocRoundTo)
			}
		}
	}
				(i+1)*calltr.AllocRoundTo)
		}
	}
	//fmt.Fprintf(w, "Memory Stats: %+v\n", calltr.CallEntryAllocStats)
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
			&ipLocalhost, 5060,
			&ipLocalhost, 5060, verbose)
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
	fmt.Fprintf(w, "uptime: %s\n\n", time.Now().Sub(StartTS))
	flags := counters.PrFullName | counters.PrVal | counters.PrDesc |
		counters.PrRec
	counters.RootGrp.Print(w, "", flags)
	counters.RootGrp.PrintSubGroups(w, flags)
}

func unescapeMsg(msg string, format string) ([]byte, error) {
	m := []byte(msg)
	f := strings.ToLower(format)
	if f == "auto" {
		if bytes.Count(m, []byte("\\r\\n")) > 5 {
			f = "escaped"
		} else if bytes.Count(m, []byte(".\r\n")) > 5 {
			f = "ngrepcrlf"
		} else if bytes.Count(m, []byte("\r\n")) > 5 {
			f = "crlf"
		} else if bytes.Count(m, []byte(".\n")) > 5 {
			f = "ngreplf"
		} else if bytes.Count(m, []byte(".\r")) > 5 {
			f = "ngrepcr"
		} else if bytes.Count(m, []byte("\n")) > 5 {
			f = "lf"
		} else if bytes.Count(m, []byte("\\n")) > 5 {
			if n, err := unescapeMsg(msg, "escaped"); err == nil {
				format = "lf"
				m = n
			} else {
				return nil, err
			}
		} else {
			f = "auto"
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
