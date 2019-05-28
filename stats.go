package sipcallmon

import (
	"fmt"
	"io"
	"strings"
	"time"

	"andrei/sipsp"
)

var StartTS time.Time

type pstats struct {
	n              uint64 // total packet count
	ip4            uint64
	ip6            uint64
	ip4frags       uint64
	ip6frags       uint64
	ip4defrag      uint64
	udpN           uint64
	udp4           uint64
	udp6           uint64
	tcpN           uint64
	tcp4           uint64
	tcp6           uint64
	sctpN          uint64
	sctp4          uint64
	sctp6          uint64
	tlsN           uint64
	dtlsN          uint64
	otherN         uint64
	decodeErrs     uint64
	injected       uint64
	seen           uint64 // actual packet seen (not filtered)
	sipUDP         uint64
	sipTCP         uint64
	callTrUDP      uint64
	callTrTCP      uint64
	callTrErrUDP   uint64
	callTrErrTCP   uint64
	tcpSyn         uint64
	tcpFin         uint64
	tcpClosed      uint64
	tcpIgn         uint64
	tcpStreamIgn   uint64
	tcpStreams     uint64
	tcpSegs        uint64
	tcpRcvd        uint64
	tcpOutOfOrder  uint64
	tcpMissed      uint64
	tcpMissedBytes uint64
	tcpRecovered   uint64
	tcpStreamTo    uint64 // streams closed due to timeout
	tcpExpReorder  uint64 // streams flushed of expired re-ordered data
	tooSmall       uint64
	tooBig         uint64
	errs           uint64
	errsUDP        uint64
	errsTCP        uint64
	offsetErr      uint64
	bodyErr        uint64
	ok             uint64
	reqsN          uint64
	replsN         uint64
	errType        [sipsp.ErrConvBug + 1]uint64
	method         [sipsp.MOther + 1]uint64
	repl           [9]uint64
}

var stats pstats

func printStats(w io.Writer) {
	fmt.Fprintf(w, "\n\nStatistics:\n")
	fmt.Fprintf(w, "%9d packets %9d ipv4 %9d ipv6 %9d other %9d inj.\n",
		stats.n, stats.ip4, stats.ip6, stats.otherN, stats.injected)
	fmt.Fprintf(w, "%9d ip4frags %9d defrag\n",
		stats.ip4frags, stats.ip4defrag)
	fmt.Fprintf(w, "%9d udp: %9d udp4 %9d upd6\n"+
		"%9d tcp: %9d tcp4 %9d tcp6\n",
		stats.udpN, stats.udp4, stats.udp6,
		stats.tcpN, stats.tcp4, stats.tcp6)
	fmt.Fprintf(w, "%9d tls %9d dtls %9d sctp \n",
		stats.tlsN, stats.dtlsN, stats.sctpN)

	fmt.Fprintf(w, "tcp: %9d streams %9d reassembled segs"+
		" %9d total bytes \n",
		stats.tcpStreams, stats.tcpSegs, stats.tcpRcvd)
	fmt.Fprintf(w, "tcp: %9d SYNs %9d FINs %9d closed \n",
		stats.tcpSyn, stats.tcpFin, stats.tcpClosed)
	fmt.Fprintf(w, "tcp: %9d ignored %9d ignored streams\n",
		stats.tcpIgn, stats.tcpStreamIgn)
	fmt.Fprintf(w, "tcp: %9d out-of-order %9d missed %9d too big\n",
		stats.tcpOutOfOrder, stats.tcpMissed, stats.tooBig)
	fmt.Fprintf(w, "tcp: %9d missed bytes\n",
		stats.tcpMissedBytes)
	fmt.Fprintf(w, "tcp: %9d stream timeouts %9d reassembly timeouts\n",
		stats.tcpStreamTo, stats.tcpExpReorder)
	fmt.Fprintf(w, "Parsed: %9d total  %9d ok   %9d errors %9d probes\n",
		stats.seen, stats.ok, stats.errs, stats.tooSmall)
	fmt.Fprintf(w, "Parsed: %9d udp ok %9d errs %9d tcp ok %9d errs\n",
		stats.sipUDP, stats.errsUDP, stats.sipTCP, stats.errsTCP)
	fmt.Fprintf(w, "Errors: %9d parse  %9d offset mismatch %9d body\n",
		stats.errs, stats.offsetErr, stats.bodyErr)
	fmt.Fprintf(w, "Tracked: %9d udp %9d tcp %9d err udp %9d err tcp\n",
		stats.callTrUDP, stats.callTrTCP,
		stats.callTrErrUDP, stats.callTrErrTCP)

	for e := 1; e < len(stats.errType); e++ {
		if stats.errType[e] != 0 {
			fmt.Fprintf(w, "	%-30q = %9d\n",
				sipsp.ErrorHdr(e), stats.errType[e])
		}
	}
	fmt.Fprintf(w, "Requests: %d \n", stats.reqsN)
	for r := 1; r < len(stats.method); r++ {
		if stats.method[r] != 0 {
			fmt.Fprintf(w, "	%-10s = %9d\n", sipsp.SIPMethod(r), stats.method[r])
		}
	}
	fmt.Fprintf(w, "Replies: %d \n", stats.replsN)
	for i, v := range stats.repl {
		if v != 0 {
			fmt.Fprintf(w, "	%1dXX = %9d\n", i, v)
		}
	}
	fmt.Fprintln(w)
}

func printStatsRaw(w io.Writer) {
	fmt.Fprintf(w, "%s\n",
		strings.Replace(fmt.Sprintf("%+v", stats), " ", "\n", -1))
}