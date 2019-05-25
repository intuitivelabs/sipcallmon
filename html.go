package main

import (
	"fmt"
	"net/http"

	"andrei/sipsp/calltr"
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

func htmlQueryEvBlst(w http.ResponseWriter, f calltr.EventFlags) {

	fmt.Fprintln(w, httpHeader)
	fmt.Fprintln(w, `<style type='text/css'> pre {display: inline;} </style`)
	fmt.Fprintln(w, `<h2>Event Blacklist</h2>`)
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
