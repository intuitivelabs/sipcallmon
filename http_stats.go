// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

// Statistics for http (reassembly) and websockets

package sipcallmon

import (
	"fmt"
	"strconv"
	"unsafe"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/httpsp"
	"github.com/intuitivelabs/sipsp"
)

// http stats
type httpStatsCounters struct {
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

	bufGrow counters.Handle
	bufMax  counters.Handle

	ok       counters.Handle
	errs     counters.Handle
	tooBig   counters.Handle
	bodyOk   counters.Handle
	bodyErrs counters.Handle
	reqsN    counters.Handle
	replsN   counters.Handle

	upgradeReq     counters.Handle
	upgradeReplOk  counters.Handle
	upgradeReplErr counters.Handle
	upgWS          counters.Handle
	upgWSSIP       counters.Handle
	errType        [httpsp.ErrConvBug + 1]counters.Handle
	method         [httpsp.MOther + 1]counters.Handle
	repl           [10]counters.Handle
}

// websocket & websocket sip stats
type wsStatsCounters struct {
	streams       counters.Handle
	errs          counters.Handle
	tooBig        counters.Handle
	sipStreams    counters.Handle
	ctrlFrames    counters.Handle
	sipFrames     counters.Handle
	sipFrags      counters.Handle
	sipCompFrames counters.Handle
	sipOk         counters.Handle
	sipEmpty      counters.Handle
	sipTooSmall   counters.Handle
	sipErr        counters.Handle
	sipErrType    [sipsp.ErrConvBug + 1]counters.Handle
}

var httpCnts httpStatsCounters
var wsCnts wsStatsCounters
var httpStats *counters.Group
var wsStats *counters.Group

func httpStatsInit() error {
	cntDefs := [...]counters.Def{
		{&httpCnts.tcpSyn, 0, nil, nil, "tcp_syn", "tcp SYNs seen"},
		{&httpCnts.tcpFin, 0, nil, nil, "tcp_fin", "tcp FINs seen"},
		{&httpCnts.tcpClosed, 0, nil, nil, "tcp_closed",
			"tcp connections closed (FIN, RST, timeout...)"},
		{&httpCnts.tcpIgn, 0, nil, nil, "tcp_ign",
			"ignored tcp segments during reassembly"},
		{&httpCnts.tcpStreamIgn, 0, nil, nil, "tcp_stream_ign",
			"ignored tcp streams on close/complete reassembly"},
		{&httpCnts.tcpStreams, 0, nil, nil, "tcp_streams",
			"number of tcp streams (uni-directional)"},
		{&httpCnts.tcpSegs, 0, nil, nil, "tcp_segs",
			"reassembled tcp segments"},
		{&httpCnts.tcpRcvd, 0, nil, nil, "tcp_total_rcvd",
			"total bytes received over tcp"},
		{&httpCnts.tcpOutOfOrder, 0, nil, nil, "tcp_out_of_order",
			"tcp out of order packets"},
		{&httpCnts.tcpMissed, 0, nil, nil, "tcp_miss",
			"tcp missed segments detected"},
		{&httpCnts.tcpMissedBytes, 0, nil, nil, "tcp_missed_bytes",
			"tcp total missed bytes"},
		{&httpCnts.tcpRecovered, 0, nil, nil, "tcp_recovered",
			"tcp stream recovered after loss"},

		{&httpCnts.bufGrow, 0, nil, nil, "buf_grow",
			"dbg: number of time the internal buffer was increased"},
		{&httpCnts.bufMax, counters.CntMaxF | counters.CntHideVal,
			nil, nil, "buf_max",
			"dbg: maximum internal buffer size"},

		{&httpCnts.ok, 0, nil, nil, "parsed_ok",
			"total number of http messages parsed successfully"},
		{&httpCnts.errs, 0, nil, nil, "parse_errs",
			"total http parse errors"},
		{&httpCnts.tooBig, 0, nil, nil, "huge_packets",
			"packets too big, dropped"},
		{&httpCnts.bodyOk, 0, nil, nil, "body_ok",
			"http body parse/skip ok"},
		{&httpCnts.bodyErrs, 0, nil, nil, "body_errs",
			"errors after attempting to parse or skip the http body"},
		{&httpCnts.reqsN, 0, nil, nil, "reqs",
			" number of http requests"},
		{&httpCnts.replsN, 0, nil, nil, "repls",
			" number of http replies"},
		{&httpCnts.upgradeReq, 0, nil, nil, "upgrade_reqs",
			"http protocol upgrade requests"},
		{&httpCnts.upgradeReplOk, 0, nil, nil, "upgrade_ok",
			"http protocol upgrade success replies"},
		{&httpCnts.upgradeReplErr, 0, nil, nil, "upgrade_err",
			"http protocol upgrade failure replies"},
		{&httpCnts.upgWS, 0, nil, nil, "upgrade_ws",
			"http protocol upgrade to websocket"},
		{&httpCnts.upgWSSIP, 0, nil, nil, "upgrade_sip",
			"http protocol upgrade to SIP websocket"},
	}
	entries := int(unsafe.Sizeof(httpCnts) / unsafe.Sizeof(httpCnts.ok))
	// register a http group with the main "pkt_stats" as parent
	err := registerCounters("http", stats, &httpStats, cntDefs[:], entries, 10)
	if err != nil {
		return err
	}
	// register the counters for the http parse errors
	for i := 0; i < len(httpCnts.errType); i++ {
		_, ok := httpStats.RegisterDef(
			&counters.Def{&httpCnts.errType[i], 0, nil, nil,
				"p_err_" + strconv.Itoa(i),
				"parse_error: " + httpsp.ErrorHdr(i).Error()})
		if !ok {
			return fmt.Errorf("failed to register http p_error_%d counter",
				i)
		}
	}
	// register the counters for the http methods
	for i := 0; i < len(httpCnts.method); i++ {
		var method, desc string
		switch httpsp.HTTPMethod(i) {
		case httpsp.MUndef:
			method = "UNDEF"
			desc = "undefined http method"
		case httpsp.MOther:
			method = httpsp.HTTPMethod(i).String()
			desc = "total number of unknown http methods"
		default:
			method = httpsp.HTTPMethod(i).String()
			desc = "total number of http " + httpsp.HTTPMethod(i).String() + "s"
		}
		_, ok := httpStats.RegisterDef(
			&counters.Def{&httpCnts.method[i], 0, nil, nil,
				"http_" + method, desc})
		if !ok {
			return fmt.Errorf("failed to register http_%s counter",
				sipsp.SIPMethod(i).String())
		}
	}
	// register the counters for the http replies
	for i := 0; i < len(httpCnts.repl); i++ {
		_, ok := httpStats.RegisterDef(
			&counters.Def{&httpCnts.repl[i], 0, nil, nil,
				"http_" + strconv.Itoa(i) + "XX",
				"total number of http " + strconv.Itoa(i) + "XX replies"})
		if !ok {
			return fmt.Errorf("failed to register %s counter",
				"http_"+strconv.Itoa(i)+"XX")
		}
	}
	return wsStatsInit()
}

func wsStatsInit() error {
	cntDefs := [...]counters.Def{
		{&wsCnts.streams, 0, nil, nil, "streams", "websocket streams"},
		{&wsCnts.errs, 0, nil, nil, "errs",
			"ws decoding errors"},
		{&wsCnts.tooBig, 0, nil, nil, "huge_packets",
			"ws packet too big, dropped"},
		{&wsCnts.sipStreams, 0, nil, nil, "sip_streams",
			"websocket sip streams"},
		{&wsCnts.ctrlFrames, 0, nil, nil, "ctrl_frames",
			"websocket control frames"},
		{&wsCnts.sipFrames, 0, nil, nil, "sip_frames", "websocket sip frames"},
		{&wsCnts.sipFrags, 0, nil, nil, "sip_frag_f",
			"websocket sip fragmented frames"},
		{&wsCnts.sipCompFrames, 0, nil, nil, "sip_comp_f",
			"websocket sip compressed frames"},
		{&wsCnts.sipOk, 0, nil, nil, "sip_ok", "sip packets parsed ok"},
		{&wsCnts.sipEmpty, 0, nil, nil, "sip_empty", "empty sip ws packets"},
		{&wsCnts.sipErr, 0, nil, nil, "sip_err",
			"total sip packets for which  parsing failed"},
		{&wsCnts.sipTooSmall, 0, nil, nil, "sip_tiny",
			"packets too small to be SIP"},
	}
	entries := int(unsafe.Sizeof(wsCnts) / unsafe.Sizeof(wsCnts.streams))
	// register a webscoket group with the "http" stats group as parent
	err := registerCounters("ws", httpStats, &wsStats, cntDefs[:], entries, 10)
	if err != nil {
		return err
	}

	// register the counters for header parse errors
	for i := 0; i < len(wsCnts.sipErrType); i++ {
		_, ok := wsStats.RegisterDef(
			&counters.Def{&wsCnts.sipErrType[i], 0, nil, nil,
				"sip_p_err_" + strconv.Itoa(i),
				"parse error: " + sipsp.ErrorHdr(i).Error()})
		if !ok {
			return fmt.Errorf("failed to register ws sip_p_error_%d counter", i)
		}
	}
	return nil
}
