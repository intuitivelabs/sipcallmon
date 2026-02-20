// Statistics ofr the ipfix tcp reassembly

package sipcallmon

import (
	"sync"

	"github.com/intuitivelabs/counters"
)

var ipfixTCPreassStatsLock sync.Mutex
var ipfixTCPreassStats *ipfixTCPreassStatsT

// ipfix tcp reassemnbly stats

type ipfixTCPreassStatsT struct {
	cnts *counters.Group

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

	tcpStreamTo   counters.Handle // streams closed due to timeout
	tcpExpReorder counters.Handle // streams flushed of expired re-ordered data

	bufGrow counters.Handle
	bufMax  counters.Handle

	ok         counters.Handle
	errs       counters.Handle
	tooBig     counters.Handle
	hdrErrs    counters.Handle
	hdrLenErrs counters.Handle
}

func (s *ipfixTCPreassStatsT) Init() bool {
	cntDefs := [...]counters.Def{
		{&s.tcpSyn, 0, nil, nil, "tcp_syn", "tcp SYNs seen"},
		{&s.tcpFin, 0, nil, nil, "tcp_fin", "tcp FINs seen"},
		{&s.tcpClosed, 0, nil, nil, "tcp_closed",
			"tcp connections closed (FIN, RST, timeout...)"},
		{&s.tcpIgn, 0, nil, nil, "tcp_ign",
			"ignored tcp segments during reassembly"},
		{&s.tcpStreamIgn, 0, nil, nil, "tcp_stream_ign",
			"ignored tcp streams on close/complete reassembly"},
		{&s.tcpStreams, 0, nil, nil, "tcp_streams",
			"number of tcp streams (uni-directional)"},
		{&s.tcpSegs, 0, nil, nil, "tcp_segs",
			"reassembled tcp segments"},
		{&s.tcpRcvd, 0, nil, nil, "tcp_total_rcvd",
			"total bytes received over tcp"},
		{&s.tcpOutOfOrder, 0, nil, nil, "tcp_out_of_order",
			"tcp out of order packets"},
		{&s.tcpMissed, 0, nil, nil, "tcp_miss",
			"tcp missed segments detected"},
		{&s.tcpMissedBytes, 0, nil, nil, "tcp_missed_bytes",
			"tcp total missed bytes"},
		{&s.tcpRecovered, 0, nil, nil, "tcp_recovered",
			"tcp stream recovered after loss"},

		{&s.tcpStreamTo, 0, nil, nil, "tcp_stream_timeouts",
			"tcp streams that did timeout"},
		{&s.tcpExpReorder, 0, nil, nil, "tcp_reorder_timeouts",
			"tcp stop waiting for out-of-order data due to timeout"},

		{&s.bufGrow, 0, nil, nil, "buf_grow",
			"dbg: number of time the internal buffer was increased"},
		{&s.bufMax,
			counters.CntNonMonoF | counters.CntMaxF | counters.CntHideVal,
			nil, nil, "buf_max", "dbg: maximum internal buffer size"},

		{&s.ok, 0, nil, nil, "parsed_ok",
			"total number of ipfix messages parsed successfully"},
		{&s.errs, 0, nil, nil, "parse_errs",
			"total ipfix parse errors"},
		{&s.tooBig, 0, nil, nil, "huge_packets",
			"packets too big, dropped"},
		{&s.hdrErrs, 0, nil, nil, "hdr_errs",
			"ipfix bad header errors"},
		{&s.hdrLenErrs, 0, nil, nil, "hdr_len_errs",
			"ipfix header bad length errors"},
	}
	entries := len(cntDefs)
	s.cnts = counters.NewGroup("ipfix_pcap", nil, entries)
	if s.cnts == nil {
		BUG("failed to create counters group\n")
		return false
	}
	if !s.cnts.RegisterDefs(cntDefs[:]) {
		BUG("failed to register counters\n")
		return false
	}

	return true
}
