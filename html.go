// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/slog"
)

var httpHeader string = `
<!DOCTYPE html>
<html>
<body>
`

var httpFooter string = `
</body>
</html>

`
var injectForm string = `

<h2>Inject Packet</h2>

<p>Paste a sip packet (ascii text)</p>

<form action="#" method="post">
	<p>Line termination format and protocol:</p>
	<select name="crlfformat">
		<option value="auto">auto detect</option>
		<option value="ngreplf">ngrep .LF</option>
		<option value="ngrepcr">ngrep .CR</option>
		<option value="ngrepcrlf">ngrep .CRLF</option>
		<option value="lf">LF standard UNIX editor</option>
		<option value="crlf">standard raw CRLF</option>
		<option value="escaped">one line \r\n escaped</option>
	</select>
	<select name="proto">
		<option value="udp">UDP</option>
		<option value="tcp">TCP</option>
		<option value="tls">TLS</option>
	</select>
	<br>
	<p> Verbose:</p>
	<select name="verbose">
		<option value="yes">Yes</option>
		<option value="no" selected>No</option>
	</select>
	<br>
	<p>SIP message</p>
	<br>
	<textarea name="sipmsg" rows="25" cols="80" wrap="off">
	</textarea>
	<br>
	<input type="submit">
</form>

`

var queryEvForm string = `


<form action="#" method="get">
	<p>Line termination format and protocol:</p>
	<select name="filter">
		<option value="auto">auto detect</option>
		<option value="ngreplf">ngrep .LF</option>
		<option value="ngrepcr">ngrep .CR</option>
		<option value="ngrepcrlf">ngrep .CRLF</option>
		<option value="lf">LF standard UNIX editor</option>
		<option value="crlf">standard raw CRLF</option>
		<option value="escaped">one line \r\n escaped</option>
	</select>
	<br>
	<p> Verbose:</p>
	<select name="isRe">
		<option value="yes">Yes</option>
		<option value="no" selected>No</option>
	</select>
	<br>
	<p>SIP message</p>
	<br>
	<textarea name="sipmsg" rows="25" cols="80" wrap="off">
	</textarea>
	<br>
	<input type="submit">
</form>

`

func htmlQueryEvFilter(w http.ResponseWriter, m map[string]EvFilterOp) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<h2>Filter Events</h2>`)
	fmt.Fprintln(w, `<form action="/events" method="get">`)
	fmt.Fprintln(w, `	Value: <input type="text" name="val" size="80">`)
	fmt.Fprintln(w, `	<input type="checkbox" name="re" id="re" value="1">`)
	fmt.Fprintln(w, `	<label for="re">RE</label><br>`)

	fmt.Fprintln(w, `	<select name="filter">`)
	for k, _ := range m {
		fmt.Fprintf(w, "		<option value=%q>%s</option>\n", k, k)
	}
	fmt.Fprintln(w, `	</select>`)
	fmt.Fprintln(w, `	Max matches: <input type="text" name="n" size="4">`)
	fmt.Fprintln(w, `	Start: <input type="text" name="s" size="4">`)
	fmt.Fprintln(w, `<input type="submit">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)

}

func htmlQueryCallFilter(w http.ResponseWriter, m map[string]int) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<h2>Filter Calls</h2>`)
	fmt.Fprintln(w, `<form action="/calls/list" method="get">`)
	fmt.Fprintln(w, `	Value: <input type="text" name="val" size="80">`)
	fmt.Fprintln(w, `	<input type="checkbox" name="re" id="re" value="1">`)
	fmt.Fprintln(w, `	<label for="re">RE</label><br>`)

	fmt.Fprintln(w, `	<select name="filter">`)
	for k, _ := range m {
		fmt.Fprintf(w, "		<option value=%q>%s</option>\n", k, k)
	}
	fmt.Fprintln(w, `	</select>`)
	fmt.Fprintln(w, `	Max matches: <input type="text" name="n" size="4">`)
	fmt.Fprintln(w, `	Start: <input type="text" name="s" size="4">`)
	fmt.Fprintln(w, `<input type="submit">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)

}

func htmlQueryRegBindingsFilter(w http.ResponseWriter, m map[string]int) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<h2>Filter Registrations Bindings</h2>`)
	fmt.Fprintln(w, `<form action="/regs/list" method="get">`)
	fmt.Fprintln(w, `	Value: <input type="text" name="val" size="80">`)
	fmt.Fprintln(w, `	<input type="checkbox" name="re" id="re" value="1">`)
	fmt.Fprintln(w, `	<label for="re">RE</label><br>`)

	fmt.Fprintln(w, `	<select name="filter">`)
	for k, _ := range m {
		fmt.Fprintf(w, "		<option value=%q>%s</option>\n", k, k)
	}
	fmt.Fprintln(w, `	</select>`)
	fmt.Fprintln(w, `	Max matches: <input type="text" name="n" size="4">`)
	fmt.Fprintln(w, `	Start: <input type="text" name="s" size="4">`)
	fmt.Fprintln(w, `<input type="submit">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)

}

func htmlQueryEvBlst(w http.ResponseWriter, f calltr.EventFlags) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Event Blacklist</h2>`)
	fmt.Fprintln(w, `<hr><br>`)
	fmt.Fprintln(w, `<form action="/events/blst" method="get">`)
	for e := calltr.EvNone + 1; e < calltr.EvBad; e++ {
		on, off := "", ""
		if f.Test(e) {
			on = "checked"
		} else {
			off = "checked"
		}
		/*	fmt.Fprintf(w, `	<input type="checkbox" name=%q id=%q value="1" %s>`,
				e.String(), e.String(), checked)
			fmt.Fprintf(w, `	<label for=%q>%s</label><br>`,
				e.String(), e.String())
		*/
		fmt.Fprintf(w, "	<div><pre>%-12s:</pre>\n", e.String())
		fmt.Fprintf(w, `	<input type="radio" name=%q id="%s_on" value="1" %s>`,
			e.String(), e.String(), on)
		fmt.Fprintf(w, `	<label for="%s_on">on</label>`,
			e.String())
		fmt.Fprintf(w, `	<input type="radio" name=%q id="%s_off" value="0" %s>`,
			e.String(), e.String(), off)
		fmt.Fprintf(w, `	<label for="%s_off">off</label>`,
			e.String())
		fmt.Fprintf(w, "	</div>\n")
	}

	fmt.Fprintln(w, `<br><input type="submit" value="Set">`)
	fmt.Fprintln(w, `<input type="submit" name="reset" value="Reset">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)
}

func htmlQueryEvRateBlst(w http.ResponseWriter) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<h2>Filter Event Rate Entries</h2>`)
	fmt.Fprintln(w, `<form action="/evrateblst/list" method="get">`)

	fmt.Fprintln(w, `Blacklisted: <select name="val">`)
	fmt.Fprintf(w, "	<option value=\"-1\">ignore</option>\n")
	fmt.Fprintf(w, "	<option value=\"0\">false</option>\n")
	fmt.Fprintf(w, "	<option value=\"1\">true</option>\n")
	fmt.Fprintln(w, `</select>`)

	fmt.Fprintln(w, "Rate:")
	fmt.Fprintln(w, ` <select name="rop">`)
	fmt.Fprintf(w, "	<option value=\">=\">&gt=</option>\n")
	fmt.Fprintf(w, "	<option value=\"<\">&lt</option>\n")
	fmt.Fprintln(w, `</select>`)
	fmt.Fprintln(w, `<input type="text" name="rate" size="4">`)
	fmt.Fprintln(w, `Rate Interval: <select name="ridx">`)
	for i := 0; i < calltr.NEvRates; i++ {
		intvl := EvRateBlst.GetRateIntvl(i)
		if intvl != 0 {
			fmt.Fprintf(w, "	<option value=\"%d\">%s</option>\n",
				i, intvl)
		}
	}
	fmt.Fprintln(w, `</select>`)

	fmt.Fprintln(w, `	IP: <input type="text" name="ip" size="20">`)
	fmt.Fprintln(w, `	<input type="checkbox" name="re" id="re" value="1">`)
	fmt.Fprintln(w, `	<label for="re">RE</label><br>`)

	fmt.Fprintln(w, `	Max matches: <input type="text" name="n" size="4">`)
	fmt.Fprintln(w, `	Start: <input type="text" name="s" size="4">`)
	fmt.Fprintln(w, `<input type="submit">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)

}

func htmlEvRateSetForm(w http.ResponseWriter) {

	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Event Blacklist Report Counts and Set Rates</h2>`)
	fmt.Fprintln(w, `<hr><div><br></div>`)
	fmt.Fprintln(w, `<form action="/evrateblst/rates" method="get">`)

	minr := atomic.LoadUint64(&RunningCfg.EvRConseqRmin)
	maxr := atomic.LoadUint64(&RunningCfg.EvRConseqRmax)
	n := "evr_conseq_report_min"
	fmt.Fprintf(w, "	<div><pre>%-22s:</pre>\n", n)
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="4">`,
		n, strconv.FormatUint(minr, 10))
	fmt.Fprintf(w, "<pre>(min. repetitions for reporting)</pre>\n")
	fmt.Fprintf(w, "	</div>\n")
	n = "evr_conseq_report_max"
	fmt.Fprintf(w, "	<div><pre>%-22s:</pre>\n", n)
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="4">`,
		n, strconv.FormatUint(maxr, 10))
	fmt.Fprintf(w, "<pre>(max. repetitions for reporting)</pre>\n")
	fmt.Fprintf(w, "	</div><br>\n")

	for i := 0; i < calltr.NEvRates; i++ {
		rname := "rate" + strconv.Itoa(i)
		rintvl := "interval" + strconv.Itoa(i)
		max := EvRateBlst.GetRateMaxVal(i)
		intvl := EvRateBlst.GetRateIntvl(i)
		fmt.Fprintf(w, "	<div><pre>%-12s:</pre>\n", rname)
		fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="4">`,
			rname, strconv.FormatFloat(max, 'f', 1, 64))
		fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="4">`,
			rintvl, intvl.String())
		fmt.Fprintf(w, "	</div>\n")
	}

	fmt.Fprintln(w, `<br><input type="submit" value="Set">`)
	fmt.Fprintln(w, `</form>`)
}

func htmlEvRateGCparams(w http.ResponseWriter, gcCfg *calltr.EvRateGCcfg) {
	fmt.Fprintln(w, httpHeader)

	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Event Blacklist Garbage Collection Parameters</h2>`)
	fmt.Fprintln(w, `<hr><div><br></div>`)
	fmt.Fprintln(w, `<form action= "/evrateblst/gccfg2" method="get">`)

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "max_entries")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6"></div>`,
		"max_entries", strconv.FormatUint(uint64(gcCfg.MaxEntries), 10))

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "hard_gc_target")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6">`,
		"hard_gc_target", strconv.FormatUint(uint64(gcCfg.TargetMax), 10))
	fmt.Fprintf(w, "<pre> (%02d%%)</pre>",
		gcCfg.TargetMax*100/gcCfg.MaxEntries,
	)
	fmt.Fprintln(w, "</div>")

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "light_gc_trigger")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6">`,
		"light_gc_trigger", strconv.FormatUint(uint64(gcCfg.GCtrigger), 10))
	fmt.Fprintf(w, "<pre> (%02d%%)</pre>",
		gcCfg.GCtrigger*100/gcCfg.MaxEntries,
	)
	fmt.Fprintln(w, "</div>")

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "light_gc_target")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6">`,
		"light_gc_target", strconv.FormatUint(uint64(gcCfg.GCtarget), 10))
	fmt.Fprintf(w, "<pre> (%02d%%)</pre>",
		gcCfg.GCtarget*100/gcCfg.MaxEntries,
	)
	fmt.Fprintln(w, "</div>")

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "light_gc_lifetime")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6">`,
		"light_gc_lifetime", gcCfg.LightGCtimeL)
	fmt.Fprintln(w, "</div>")

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "light_gc_max_runtime")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6">`,
		"light_gc_runtime", gcCfg.LightGCrunL)
	fmt.Fprintln(w, "</div>")

	fmt.Fprintf(w, "	<br><div><pre>%-20s:</pre>\n", "hard_gc_criteria")
	for i, m := range *gcCfg.ForceGCMatchC {
		htmlEvRateMatchEv(w, "hard_gc_m"+strconv.Itoa(i), m)
		fmt.Fprintf(w, "	<br>\n")
	}
	fmt.Fprintf(w, "</div>\n")

	fmt.Fprintf(w, "	<br><div><pre>%-20s:</pre>\n",
		"hard_gc_run_limits")
	for i, l := range *gcCfg.ForceGCrunL {
		fmt.Fprintf(w, "	  <div><pre>%-18s:</pre>\n",
			"for criteria "+strconv.Itoa(i))
		fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
			"rlim"+strconv.Itoa(i), l)
		fmt.Fprintf(w, "\n	  </div>\n")
		fmt.Fprintf(w, "	<br>\n")
	}
	fmt.Fprintf(w, "	</div>\n")

	fmt.Fprintln(w, `<br><input type="submit" value="Set">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)
}

func htmlEvRateMatchEv(w http.ResponseWriter, n string, m calltr.MatchEvROffs) {
	fmt.Fprintf(w, "	  <div><pre>%-18s:</pre>\n", "blacklisted")
	selectMatchEvOp(w, n+"_opex", m.OpEx)
	fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
		n+"_ex", strconv.FormatBool(m.Ex))
	fmt.Fprintf(w, "</div>\n")

	fmt.Fprintf(w, "		<div><pre>%-18s:</pre>", "created")
	selectMatchEvOp(w, n+"_opt0", m.OpT0)
	fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
		n+"_dt0", m.DT0)
	fmt.Fprintf(w, "</div>\n")

	fmt.Fprintf(w, "		<div><pre>%-18s:</pre>", "changed")
	selectMatchEvOp(w, n+"_opexchgt", m.OpExChgT)
	fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
		n+"_dexchgt", m.DExChgT)
	fmt.Fprintf(w, "</div>\n")

	fmt.Fprintf(w, "		<div><pre>%-18s:</pre>", "last blacklisted")
	selectMatchEvOp(w, n+"_opexlastt", m.OpExLastT)
	fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
		n+"_dexlastt", m.DExLastT)
	fmt.Fprintf(w, "</div>\n")

	fmt.Fprintf(w, "		<div><pre>%-18s:</pre>", "last ok")
	selectMatchEvOp(w, n+"_opoklastt", m.OpOkLastT)
	fmt.Fprintf(w, `		<input type="text" name=%q  value=%q size="4">`,
		n+"_doklastt", m.DOkLastT)
	fmt.Fprintf(w, "</div>\n")

}

func selectMatchEvOp(w http.ResponseWriter, n string, defOp calltr.MatchOp) {
	fmt.Fprintf(w, "		<select name=%q>\n", n)
	for op := calltr.MatchOp(0); op <= calltr.MOpLast; op++ {
		opstr := op.String()
		if len(opstr) != 0 {
			selected := ""
			if op == defOp {
				selected = "selected"
			}
			fmt.Fprintf(w, "			<option value=%q %s>%s</option>\n",
				opstr, selected, html.EscapeString(opstr))
		}
	}
	fmt.Fprintln(w, `		</select>`)
}

func htmlEvRatePerGCparams(w http.ResponseWriter, cfg *Config) {
	interval := time.Duration(
		atomic.LoadInt64((*int64)(&cfg.EvRgcInterval)))
	lifetime := time.Duration(
		atomic.LoadInt64((*int64)(&cfg.EvRgcOldAge)))
	maxRunT := time.Duration(
		atomic.LoadInt64((*int64)(&cfg.EvRgcMaxRunT)))
	target := atomic.LoadUint64(&cfg.EvRgcTarget)

	fmt.Fprintln(w, httpHeader)

	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Event Blacklist Periodic Garbage Collection Cfg</h2>`)
	fmt.Fprintln(w, `<hr><div><br></div>`)
	fmt.Fprintln(w, `<form action= "/evrateblst/gccfg1" method="get">`)

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "evr_gc_interval")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6"></div>`,
		"evr_gc_interval", interval)

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "evr_gc_old_age")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6"></div>`,
		"evr_gc_old_age", lifetime)

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "evr_gc_max_run_time")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6"></div>`,
		"evr_gc_max_run_time", maxRunT)

	fmt.Fprintf(w, "	<div><pre>%-20s:</pre>\n", "evr_gc_target")
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="6"></div>`,
		"evr_gc_target", strconv.FormatUint(target, 10))

	fmt.Fprintln(w, `<br><input type="submit" value="Set">`)
	fmt.Fprintln(w, `</form>`)

	fmt.Fprintln(w, httpFooter)
}

// print a form input field.
// Parameters: n - name,
//             nAlign - allign to this many chars
//             defVal - default value (pre-filled)
//             fSize  - field size
//             comment - optional comment (printed after the input field)
func htmlInputField(w http.ResponseWriter, n string, nAlign int,
	defVal string, fSize int, comment string) {
	align := ""
	if nAlign != 0 {
		align = strconv.Itoa(nAlign)
	}
	fmt.Fprintf(w, "	<div><pre>%"+align+"s:</pre>\n", n)
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="%d">`,
		n, defVal, fSize)
	if comment != "" {
		fmt.Fprintf(w, "<pre>    %s</pre>\n", comment)
	}
	fmt.Fprintf(w, "	</div>\n")
}

// print a form composed of 1 input field.
// Parameters:
//            actionUrl
//             n       - name,
//             nAlign  - allign to this many chars
//             defVal  - default value (pre-filled)
//             fSize   - field size
//             comment - optional comment (printed after the input field)
//             submit  - name for the submit button
func htmlInputForm1V(w http.ResponseWriter, actionUrl, n string,
	nAlign int, defVal string, fSize int, comment string, submit string) {

	fmt.Fprintln(w, `<form action="`, actionUrl, `" method="get">`)
	align := ""
	if nAlign != 0 {
		align = strconv.Itoa(nAlign)
	}
	fmt.Fprintln(w, `<span class="input text">`)
	fmt.Fprintf(w, "	<pre>%"+align+"s:</pre>\n", n)
	fmt.Fprintf(w, `	<input type="text" name=%q  value=%q size="%d">`,
		n, defVal, fSize)
	fmt.Fprintln(w, `</span><span class="submit">`)
	fmt.Fprintln(w, `<input type="submit" value="Set"></span>`)
	if comment != "" {
		fmt.Fprintf(w, "<pre>    %s</pre>\n", comment)
	}
	fmt.Fprintf(w, "	\n")
	fmt.Fprintln(w, `</form>`)
}

func htmlDbgOptsSetForm(w http.ResponseWriter) {
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Logging and debugging options</h2>`)
	fmt.Fprintln(w, `<hr><div><br></div>`)
	fmt.Fprintln(w, `<form action="/debug/options" method="get">`)

	logLev := atomic.LoadInt64(&RunningCfg.LogLev)
	levVals := ""
	for i := slog.LMIN; i <= slog.LMAX; i++ {
		levVals += slog.LevelName(i) + ":" + strconv.FormatInt(int64(i), 10)
		if i != slog.LMAX {
			levVals += ", "
		}
	}
	htmlInputField(w, "log_level", -22, strconv.FormatInt(logLev, 10), 3,
		"general log level: "+slog.LevelName(slog.LogLevel(logLev)))
	fmt.Fprintf(w, "	<div><pre>(possible Values: %s)</pre></div><br>\n",
		levVals)
	logOpt := atomic.LoadUint64(&RunningCfg.LogOpt)
	crtValStr, _ := slog.LogOptString(slog.LogOptions(logOpt))
	optVals := ""
	for i := 0; i < int(unsafe.Sizeof(slog.LogOptions(0))*8); i++ {
		if n, ok := slog.LogOptString(slog.LogOptions(1 << i)); ok {
			if optVals != "" {
				optVals += ", "
			}
			optVals += n + ":" + strconv.FormatUint(1<<i, 10)
		} else {
			break
		}
	}
	htmlInputField(w, "log_opt", -22, strconv.FormatUint(logOpt, 10), 3,
		"general log flags:"+crtValStr,
	)
	fmt.Fprintf(w, "	<div><pre>(possible Values: %s)</pre></div><br>\n",
		optVals)

	pLogLev := atomic.LoadInt64(&RunningCfg.ParseLogLev)
	pLevStr := slog.LevelName(slog.LogLevel(pLogLev))
	htmlInputField(w, "parse_log_level", -22, strconv.FormatInt(pLogLev, 10),
		3, "parser/capture log level: "+pLevStr+
			" (same values as for log_level)")
	pLogOpt := atomic.LoadUint64(&RunningCfg.ParseLogOpt)
	pOptStr, _ := slog.LogOptString(slog.LogOptions(pLogOpt))
	htmlInputField(w, "parse_log_opt", -22, strconv.FormatUint(pLogOpt, 10), 3,
		"parser/caputure options flags:"+pOptStr+
			" (same values as for log_opt)")

	fmt.Fprintf(w, "	<br>\n")
	dbgCalltr := atomic.LoadUint64(&RunningCfg.DbgCalltr)
	htmlInputField(w, "debug_calltr", -22, strconv.FormatUint(dbgCalltr, 10),
		3, "debug flags for call tracking: alloc: 1")

	fmt.Fprintln(w, `<br><input type="submit" value="Set">`)
	fmt.Fprintln(w, `</form>`)
}

func htmlQueryCallStTimeout(w http.ResponseWriter, footer string) {

	url := "/calls/timeout" // target action url
	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Call State Timeout (s)</h2>`)
	fmt.Fprintln(w, `<hr><br>`)
	for cs := calltr.CallStNone + 1; cs < calltr.CallStNumber; cs++ {
		n := cs.Name()
		v := time.Duration(cs.TimeoutS()) * time.Second
		htmlInputForm1V(w, url, n, -16, v.String(), 6, cs.Desc(), "Set")
	}
	fmt.Fprintln(w, `<br><small>(note: a 0 value reverts`+
		` back to the default)</small><br><br>`)

	fmt.Fprintln(w, footer)
	fmt.Fprintln(w, httpFooter)
}

func htmlQueryTCPTimeout(w http.ResponseWriter, cfg *Config, footer string) {

	url := "/tcp/timeouts" // target action url
	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>TCP Timeouts</h2>`)
	fmt.Fprintln(w, `<hr><br>`)

	v := time.Duration(
		atomic.LoadInt64((*int64)(&cfg.TCPGcInt)))
	htmlInputForm1V(w, url, "tcp_gc_int", -23, v.String(), 6,
		"frequency for checking the other tcp timeouts", "Set")

	v = time.Duration(
		atomic.LoadInt64((*int64)(&cfg.TCPReorderTo)))
	htmlInputForm1V(w, url, "tcp_reorder_timeout", -23, v.String(), 6,
		"wait timeout for reordered segments", "Set")

	v = time.Duration(
		atomic.LoadInt64((*int64)(&cfg.TCPConnTo)))
	htmlInputForm1V(w, url, "tcp_connection_timeout", -23, v.String(), 6,
		"timeout for closing streams on which no packets have been seen",
		"Set")

	fmt.Fprintln(w, `<br><small>(note: a 0 value reverts`+
		` back to the default)</small><br><br>`)

	fmt.Fprintln(w, footer)
	fmt.Fprintln(w, httpFooter)
}

func htmlRegCfg(w http.ResponseWriter, ccfg *calltr.Config, footer string) {

	url := "/regs/cfg" // target action url
	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style>`)
	fmt.Fprintln(w, `<h2>Register Handling Config</h2>`)
	fmt.Fprintln(w, `<hr><br>`)

	rDelta := uint64(ccfg.RegDelta)
	htmlInputForm1V(w, url, "reg_exp_delta", -23,
		strconv.FormatUint(rDelta, 10), 6,
		"extra REGISTER expiration delta in s, for absorbing "+
			"delayed re-REGISTERs",
		"Set")

	rDelay := int64(ccfg.RegDelDelay)
	htmlInputForm1V(w, url, "reg_del_delay", -23,
		strconv.FormatInt(rDelay, 10), 6,
		"RegDel event generation delay in s, to work around quick reg.del"+
			" re-reg",
		"Set")

	ignPort := int64(0)
	if ccfg.ContactIgnorePort {
		ignPort = 1
	}
	htmlInputForm1V(w, url, "contact_ignore_port", -23,
		strconv.FormatInt(ignPort, 10), 6,
		"ignore port number when comparing contacts (but not AORs)",
		"Set")

	fmt.Fprintln(w, `<br><small>(note: a -1 value reverts`+
		` back to the default)</small><br><br>`)

	fmt.Fprintln(w, footer)
	fmt.Fprintln(w, httpFooter)
}
