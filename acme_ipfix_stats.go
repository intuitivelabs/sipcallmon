package sipcallmon

import (
	"sync"

	"github.com/intuitivelabs/counters"
)

var acmeIPFIXstatsLock sync.Mutex
var acmeIPFIXstats *acmeIPFIXstatsT

type acmeIPFIXstatsT struct {
	cnts *counters.Group

	hActiveConns counters.Handle
	hTotalConns  counters.Handle

	hTemplateSet        counters.Handle
	hOptionsTemplateSet counters.Handle
	hUnknownSet         counters.Handle

	hKeepAlive   counters.Handle
	hConnReq     counters.Handle
	hSIPudp4In   counters.Handle
	hSIPudp4Out  counters.Handle
	hSIPtcp4In   counters.Handle
	hSIPtcp4Out  counters.Handle
	hSIPsctp4In  counters.Handle
	hSIPsctp4Out counters.Handle

	hMaxSetsPkt counters.Handle
	hMaxPadding counters.Handle
	hPaddedSets counters.Handle
	hShortRead  counters.Handle
	hLongRead   counters.Handle

	hWrPkts  counters.Handle
	hWrBytes counters.Handle
	hRdPkts  counters.Handle
	hRdBytes counters.Handle

	hPktParseErr counters.Handle
	hBUG         counters.Handle
}

func (s *acmeIPFIXstatsT) Init() bool {
	cntDefs := [...]counters.Def{
		{&s.hActiveConns, counters.CntMaxF, nil, nil, "conns_active",
			"active acme ipfix connections"},
		{&s.hTotalConns, 0, nil, nil, "conns_total",
			"total opened acme ipfix connections"},

		{&s.hTemplateSet, 0, nil, nil, "template_sets",
			"total template sets received"},
		{&s.hOptionsTemplateSet, 0, nil, nil, "opt_template_sets",
			"total option template sets received"},
		{&s.hUnknownSet, 0, nil, nil, "unknown_sets",
			"unknown sets received"},

		{&s.hKeepAlive, 0, nil, nil, "keepalives",
			"number of KeepAlives received"},
		{&s.hConnReq, 0, nil, nil, "conn_open",
			"number of probe connection open requests"},
		{&s.hSIPudp4In, 0, nil, nil, "sip_udp4_in",
			"number of ingress SIP over IPv4 UDP data sets received"},
		{&s.hSIPudp4Out, 0, nil, nil, "sip_udp4_out",
			"number of egress SIP over IPv4 UDP data sets received"},
		{&s.hSIPtcp4In, 0, nil, nil, "sip_tcp4_in",
			"number of ingress SIP over IPv4 TCP data sets received"},
		{&s.hSIPtcp4Out, 0, nil, nil, "sip_tcp4_out",
			"number of egress SIP over IPv4 TCP data sets received"},
		{&s.hSIPsctp4In, 0, nil, nil, "sip_sctp4_in",
			"number of ingress SIP over IPv4 SCTP data sets received"},
		{&s.hSIPsctp4Out, 0, nil, nil, "sip_sctp4_out",
			"number of egress SIP over IPv4 SCTP data sets received"},

		{&s.hMaxSetsPkt, counters.CntMaxF | counters.CntNonMonoF, nil, nil,
			"max_sets",
			"max IPFIX sets received per packet (dbg)"},
		{&s.hMaxPadding, counters.CntMaxF | counters.CntNonMonoF, nil, nil,
			"max_padding",
			"max IPFIX sets padding seen (dbg)"},
		{&s.hPaddedSets, 0, nil, nil, "padded_sets",
			"number of paddes IPFIX sets seen (dbg)"},
		{&s.hShortRead, 0, nil, nil, "short_read",
			"socket reads less then a packet (dbg)"},
		{&s.hLongRead, 0, nil, nil, "long_read",
			"socket reads more then a packet (dbg)"},

		{&s.hWrPkts, 0, nil, nil, "pkts_sent",
			"number of sent packets (connection open acks)"},
		{&s.hWrBytes, 0, nil, nil, "bytes_sent",
			"number of bytes sent (connection open acks)"},
		{&s.hRdPkts, 0, nil, nil, "pkts_rcvd",
			"number of packets received"},
		{&s.hRdBytes, 0, nil, nil, "bytes_rcvd",
			"number of bytes received"},

		{&s.hPktParseErr, 0, nil, nil, "err_parse",
			"number of packet parse errors"},
		{&s.hBUG, 0, nil, nil, "err_bug",
			"number of detected BUGs (dbg)"},
	}

	entries := len(cntDefs)
	s.cnts = counters.NewGroup("ipfix", nil, entries)
	if s.cnts == nil {
		BUG("failed to register counters\n")
		return false
	}
	if !s.cnts.RegisterDefs(cntDefs[:]) {
		BUG("failed to register counters\n")
		return false
	}
	return true
}
