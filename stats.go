// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"io"
	//"reflect"
	//"strings"
	"strconv"
	"time"
	"unsafe"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

var StartTS time.Time
var StopTS time.Time // when set it's the stop time (pcap mode & end of input)

type statsCounters struct {
	n              counters.Handle // total packet count
	tsize          counters.Handle // total size of all the packets (on the wire)
	ip4            counters.Handle
	ip6            counters.Handle
	ip4frags       counters.Handle
	ip6frags       counters.Handle
	ip4defrag      counters.Handle
	udpN           counters.Handle
	udp4           counters.Handle
	udp6           counters.Handle
	tcpN           counters.Handle
	tcp4           counters.Handle
	tcp6           counters.Handle
	sctpN          counters.Handle
	sctp4          counters.Handle
	sctp6          counters.Handle
	tlsN           counters.Handle
	dtlsN          counters.Handle
	vxlanN         counters.Handle
	vxlan4         counters.Handle
	vxlan6         counters.Handle
	otherN         counters.Handle
	decodeErrs     counters.Handle
	injected       counters.Handle
	seen           counters.Handle // actual packet seen (not filtered)
	sipUDP         counters.Handle
	sipTCP         counters.Handle
	callTrUDP      counters.Handle
	callTrTCP      counters.Handle
	callTrErrUDP   counters.Handle
	callTrErrTCP   counters.Handle
	tcpSyn         counters.Handle
	tcpFin         counters.Handle
	tcpClosed      counters.Handle
	tcpIgn         counters.Handle
	tcpStreamIgn   counters.Handle
	tcpStreams     counters.Handle
	tcpSegs        counters.Handle
	tcpRcvd        counters.Handle
	tcpOutOfOrder  counters.Handle
	tcpMissed      counters.Handle
	tcpMissedBytes counters.Handle
	tcpRecovered   counters.Handle
	tcpStreamTo    counters.Handle // streams closed due to timeout
	tcpExpReorder  counters.Handle // streams flushed of expired re-ordered data
	tooSmall       counters.Handle
	tooBig         counters.Handle
	errs           counters.Handle
	errsUDP        counters.Handle
	errsTCP        counters.Handle
	offsetErr      counters.Handle
	bodyErr        counters.Handle
	ok             counters.Handle
	reqsN          counters.Handle
	replsN         counters.Handle
	errType        [sipsp.ErrConvBug + 1]counters.Handle
	method         [sipsp.MOther + 1]counters.Handle
	repl           [10]counters.Handle
}

var stats *counters.Group
var sCnts statsCounters

type recStats struct {
	Delta    time.Duration
	t0       time.Time
	updated  time.Time
	s0       counters.Group
	rate     counters.Group
	s0Root   counters.Group
	rateRoot counters.Group
}

var statsRate = [...]recStats{
	{Delta: 1 * time.Second},
	{Delta: 10 * time.Second},
	{Delta: 1 * time.Minute},
	{Delta: 1 * time.Hour},
}

func statsInit() error {

	cntDefs := [...]counters.Def{
		{&sCnts.n, 0, nil, nil, "total_packets", "total packet count"},
		{&sCnts.tsize, 0, nil, nil, "total_size",
			"total size of all the packets (on the wire)"},
		{&sCnts.ip4, 0, nil, nil, "ip4", "ipv4 packets"},
		{&sCnts.ip6, 0, nil, nil, "ip6", "ipv6 packets"},
		{&sCnts.ip4frags, 0, nil, nil, "ip4_frags", "ipv4 fragments"},
		{&sCnts.ip6frags, 0, nil, nil, "ip6_frags", "ipv6 fragments"},
		{&sCnts.ip4defrag, 0, nil, nil, "ip4_defrag",
			"number of defragemented ipv4 packets"},
		{&sCnts.udpN, 0, nil, nil, "udp", "udp total packets"},
		{&sCnts.udp4, 0, nil, nil, "udp4", "udp ipv4 packets"},
		{&sCnts.udp6, 0, nil, nil, "udp6", "udp ipv6 packets"},
		{&sCnts.tcpN, 0, nil, nil, "tcp", "tcp total packets"},
		{&sCnts.tcp4, 0, nil, nil, "tcp4", "tcp ipv4 packets"},
		{&sCnts.tcp6, 0, nil, nil, "tcp6", "tcp ipv6 packets"},
		{&sCnts.sctpN, 0, nil, nil, "sctp", "sctp total packets"},
		{&sCnts.sctp4, 0, nil, nil, "sctp4", "sctp ipv4 packets"},
		{&sCnts.sctp6, 0, nil, nil, "sctp6", "sctp ipv6 packets"},
		{&sCnts.tlsN, 0, nil, nil, "tls", "tls packets"},
		{&sCnts.dtlsN, 0, nil, nil, "dtls", "dtls packets"},
		{&sCnts.vxlanN, 0, nil, nil, "vxlan", "vxlan total packets"},
		{&sCnts.vxlan4, 0, nil, nil, "vxlan4", "ipv4 vxlan packets"},
		{&sCnts.vxlan6, 0, nil, nil, "vxlan6", "ipv6 vxlan packets"},
		{&sCnts.otherN, 0, nil, nil, "other",
			"other unknown transport or network layer packets"},
		{&sCnts.decodeErrs, 0, nil, nil, "decode_errs",
			"packet network layer decode errors"},
		{&sCnts.injected, 0, nil, nil, "injected",
			"injected packets (local web interface)"},
		{&sCnts.seen, 0, nil, nil, "parse_attempts",
			"packets attempted to be parsed"},
		{&sCnts.sipUDP, 0, nil, nil, "sip_udp",
			"sip over udp packets, parsed ok"},
		{&sCnts.sipTCP, 0, nil, nil, "sip_tcp",
			"sip over tcp packets, parsed ok"},
		{&sCnts.callTrUDP, 0, nil, nil, "tracked_ok_udp",
			"successfully call tracked udp packets"},
		{&sCnts.callTrTCP, 0, nil, nil, "tracked_ok_tcp",
			"successfully call tracked tcp packets"},
		{&sCnts.callTrErrUDP, 0, nil, nil, "tracked_err_udp",
			"call tracking errors for udp packets"},
		{&sCnts.callTrErrTCP, 0, nil, nil, "tracked_err_tcp",
			"call tracking errors for tcp packets"},
		{&sCnts.tcpSyn, 0, nil, nil, "tcp_syn", "tcp SYNs seen"},
		{&sCnts.tcpFin, 0, nil, nil, "tcp_fin", "tcp FINs seen"},
		{&sCnts.tcpClosed, 0, nil, nil, "tcp_closed",
			"tcp connections closed (FIN, RST, timeout...)"},
		{&sCnts.tcpIgn, 0, nil, nil, "tcp_ign",
			"ignored tcp segments during reassembly"},
		{&sCnts.tcpStreamIgn, 0, nil, nil, "tcp_stream_ign",
			"ignored tcp streams on close/complete reassembly"},
		{&sCnts.tcpStreams, 0, nil, nil, "tcp_streams",
			"number of tcp streams (uni-directional)"},
		{&sCnts.tcpSegs, 0, nil, nil, "tcp_segs",
			"reassembled tcp segments"},
		{&sCnts.tcpRcvd, 0, nil, nil, "tcp_total_rcvd",
			"total bytes received over tcp"},
		{&sCnts.tcpOutOfOrder, 0, nil, nil, "tcp_out_of_order",
			"tcp out of order packets"},
		{&sCnts.tcpMissed, 0, nil, nil, "tcp_miss",
			"tcp missed segments detected"},
		{&sCnts.tcpMissedBytes, 0, nil, nil, "tcp_missed_bytes",
			"tcp total missed bytes"},
		{&sCnts.tcpRecovered, 0, nil, nil, "tcp_recovered",
			"tcp stream recovered after loss"},
		{&sCnts.tcpStreamTo, 0, nil, nil, "tcp_stream_timeouts",
			"tcp streams that did timeout"},
		{&sCnts.tcpExpReorder, 0, nil, nil, "tcp_reorder_timeouts",
			"tcp stop waiting for out-of-order data due to timeout"},
		{&sCnts.tooSmall, 0, nil, nil, "tiny_packets",
			"packets too small to be SIP (e.g. probes)"},
		{&sCnts.tooBig, 0, nil, nil, "huge_packets",
			"packets too big (on tcp)"},
		{&sCnts.errs, 0, nil, nil, "parse_errs",
			"total sip parse errors"},
		{&sCnts.errsUDP, 0, nil, nil, "parse_errs_udp",
			"sip parse errors for udp packets"},
		{&sCnts.errsTCP, 0, nil, nil, "parse_errs_tcp",
			"sip parse errors for tcp packets"},
		{&sCnts.offsetErr, 0, nil, nil, "offset_errs",
			"sip parse offset mismatch (possible incomplete packet)"},
		{&sCnts.bodyErr, 0, nil, nil, "body_errs",
			"sip message body end mismatch (possible incomplete body)"},
		{&sCnts.ok, 0, nil, nil, "parse_ok",
			"total sip messages parsed successfully "},
		{&sCnts.reqsN, 0, nil, nil, "sip_reqs", "number of sip requests"},
		{&sCnts.replsN, 0, nil, nil, "sip_repls", "number of sip replies"},
	}

	entries := int(unsafe.Sizeof(sCnts) / unsafe.Sizeof(sCnts.n))
	err := registerCounters("pkt_stats", &stats, cntDefs[:], entries, 10)
	if err != nil {
		return err
	}

	// register the counters for header parse errors
	for i := 0; i < len(sCnts.errType); i++ {
		_, ok := stats.RegisterDef(
			&counters.Def{&sCnts.errType[i], 0, nil, nil,
				"parse_error_" + strconv.Itoa(i), sipsp.ErrorHdr(i).Error()})
		if !ok {
			return fmt.Errorf("failed to register parse_error_%d counter", i)
		}
	}

	// register the counters for sip requests methods
	for i := 0; i < len(sCnts.method); i++ {
		var method, desc string
		switch sipsp.SIPMethod(i) {
		case sipsp.MUndef:
			method = "UNDEF"
			desc = "undefined sip method"
		case sipsp.MOther:
			method = sipsp.SIPMethod(i).String()
			desc = "total number of unknown sip methods"
		default:
			method = sipsp.SIPMethod(i).String()
			desc = "total number of sip " + sipsp.SIPMethod(i).String() + "s"
		}
		_, ok := stats.RegisterDef(
			&counters.Def{&sCnts.method[i], 0, nil, nil,
				"sip_" + method, desc})
		if !ok {
			return fmt.Errorf("failed to register sip_%s counter",
				sipsp.SIPMethod(i).String())
		}
	}

	// register the counters for replies statuses
	for i := 0; i < len(sCnts.repl); i++ {
		_, ok := stats.RegisterDef(
			&counters.Def{&sCnts.repl[i], 0, nil, nil,
				"sip_" + strconv.Itoa(i) + "XX",
				"total number of sip " + strconv.Itoa(i) + "XX replies"})
		if !ok {
			return fmt.Errorf("failed to register %s counter",
				"sip_"+strconv.Itoa(i)+"XX")
		}
	}
	return nil
}

func statsRecRate(ts time.Time, crt *counters.Group, sr []recStats) {
	for i := 0; i < len(sr); i++ {
		if !sr[i].t0.IsZero() { // if init
			if ts.Add(-sr[i].Delta).After(sr[i].t0) {
				// update only if at least Delta passed since last update
				statsComputeRate(&sr[i].rate, crt, &sr[i].s0,
					ts.Sub(sr[i].t0), sr[i].Delta)
				sr[i].updated = ts
				counters.CopyGrp(&sr[i].s0, crt, true)
				sr[i].t0 = ts
			}
		} else {
			// set initial values
			sr[i].t0 = ts
			s0Name := crt.Name + "_last_" + sr[i].Delta.String()
			sr[i].s0.Init(s0Name, &sr[i].s0Root, crt.MaxCntNo())
			counters.CopyGrp(&sr[i].s0, crt, true)
			rateName := crt.Name + "_rate_" + sr[i].Delta.String()
			sr[i].rate.Init(rateName, &sr[i].rateRoot, crt.MaxCntNo())
		}
	}
}

// statsComputeRate will compute the rate and return 0 on success.
func statsComputeRate(dst, crt, old *counters.Group,
	interval, unit time.Duration) int {
	delta := float64(interval)
	if unit != 0 {
		delta = delta / float64(unit)
	}
	return counters.FillRate(dst, crt, old, delta, true)
}

func printStats(w io.Writer, stats *counters.Group, sCnts *statsCounters) {
	fmt.Fprintf(w, "\n\nStatistics:\n")
	fmt.Fprintf(w, "%9d packets %9d ipv4 %9d ipv6 %9d inj.\n",
		stats.Get(sCnts.n), stats.Get(sCnts.ip4), stats.Get(sCnts.ip6),
		stats.Get(sCnts.injected))
	fmt.Fprintf(w, "%9d ip4frags %8d defrag\n",
		stats.Get(sCnts.ip4frags), stats.Get(sCnts.ip4defrag))
	fmt.Fprintf(w, "%9d udp: %9d udp4 %9d udp6\n"+
		"%9d tcp: %9d tcp4 %9d tcp6\n",
		stats.Get(sCnts.udpN), stats.Get(sCnts.udp4), stats.Get(sCnts.udp6),
		stats.Get(sCnts.tcpN), stats.Get(sCnts.tcp4), stats.Get(sCnts.tcp6))
	fmt.Fprintf(w, "%9d tls  %9d dtls %9d sctp %9d other\n",
		stats.Get(sCnts.tlsN), stats.Get(sCnts.dtlsN), stats.Get(sCnts.sctpN),
		stats.Get(sCnts.otherN))
	fmt.Fprintf(w, "%9d vxlan: %7d vxlan4 %7d vxlan6\n",
		stats.Get(sCnts.vxlanN),
		stats.Get(sCnts.vxlan4), stats.Get(sCnts.vxlan6))

	fmt.Fprintf(w, "tcp: %9d streams %9d reassembled segs"+
		" %9d total bytes \n",
		stats.Get(sCnts.tcpStreams), stats.Get(sCnts.tcpSegs),
		stats.Get(sCnts.tcpRcvd))
	fmt.Fprintf(w, "tcp: %9d SYNs %9d FINs %9d closed \n",
		stats.Get(sCnts.tcpSyn), stats.Get(sCnts.tcpFin),
		stats.Get(sCnts.tcpClosed))
	fmt.Fprintf(w, "tcp: %9d ignored %9d ignored streams\n",
		stats.Get(sCnts.tcpIgn), stats.Get(sCnts.tcpStreamIgn))
	fmt.Fprintf(w, "tcp: %9d out-of-order %9d missed %9d too big\n",
		stats.Get(sCnts.tcpOutOfOrder), stats.Get(sCnts.tcpMissed),
		stats.Get(sCnts.tooBig))
	fmt.Fprintf(w, "tcp: %9d missed bytes\n",
		stats.Get(sCnts.tcpMissedBytes))
	fmt.Fprintf(w, "tcp: %9d stream timeouts %9d reassembly timeouts\n",
		stats.Get(sCnts.tcpStreamTo), stats.Get(sCnts.tcpExpReorder))
	fmt.Fprintf(w, "Parsed: %9d total  %9d ok   %9d errors %9d probes\n",
		stats.Get(sCnts.seen), stats.Get(sCnts.ok),
		stats.Get(sCnts.errs), stats.Get(sCnts.tooSmall))
	fmt.Fprintf(w, "Parsed: %9d udp ok %9d errs %9d tcp ok %9d errs\n",
		stats.Get(sCnts.sipUDP), stats.Get(sCnts.errsUDP),
		stats.Get(sCnts.sipTCP), stats.Get(sCnts.errsTCP))
	fmt.Fprintf(w, "Errors: %9d parse  %9d offset mismatch %9d body\n",
		stats.Get(sCnts.errs), stats.Get(sCnts.offsetErr),
		stats.Get(sCnts.bodyErr))
	fmt.Fprintf(w, "Tracked: %9d udp %9d tcp %9d err udp %9d err tcp\n",
		stats.Get(sCnts.callTrUDP), stats.Get(sCnts.callTrTCP),
		stats.Get(sCnts.callTrErrUDP), stats.Get(sCnts.callTrErrTCP))

	for e := 1; e < len(sCnts.errType); e++ {
		if stats.Get(sCnts.errType[e]) != 0 {
			fmt.Fprintf(w, "	%-30q = %9d\n",
				sipsp.ErrorHdr(e), stats.Get(sCnts.errType[e]))
		}
	}
	fmt.Fprintf(w, "Requests: %d \n", stats.Get(sCnts.reqsN))
	for r := 1; r < len(sCnts.method); r++ {
		if stats.Get(sCnts.method[r]) != 0 {
			fmt.Fprintf(w, "	%-10s = %9d\n", sipsp.SIPMethod(r),
				stats.Get(sCnts.method[r]))
		}
	}
	fmt.Fprintf(w, "Replies: %d \n", stats.Get(sCnts.replsN))
	for i := 0; i < len(sCnts.repl); i++ {
		v := stats.Get(sCnts.repl[i])
		if v != 0 {
			fmt.Fprintf(w, "	%1dXX = %9d\n", i, v)
		}
	}
	fmt.Fprintln(w)
}

func printStatsRaw(w io.Writer, stats *counters.Group) {
	for i := counters.Handle(0); i < counters.Handle(stats.CntNo()); i++ {
		fmt.Fprintf(w, "%s: %d\n",
			stats.GetName(i), stats.Get(i))
	}
}
