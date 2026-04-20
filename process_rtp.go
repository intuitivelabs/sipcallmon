package sipcallmon

import (
	"net"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/timestamp"
)

// processRTP packet checks if the packet is an RTP candidate and
//
//	if so, it tries to find a matching rtp stream, update it
//	and add the packet to the corresponding pcap.
//
// returns  rtp candidate (true/false), rtp match type (RTPNoMatch,...),
//
//	pcap dump queued (true/false) and pcap dump error
//
// If the first return is false => the packet is not candidate for RTP
// (might be something else)
func processRTP(cfg *Config, srcIP net.IP, sport int, dstIP net.IP, dport int,
	ts timestamp.TS, payload []byte) (isRTP bool, rtpMatch calltr.RTPMatchT,
	pcapDump bool, pcapErr error) {

	isRTP = false
	rtpMatch = calltr.RTPNoMatch
	pcapDump = false
	// check if configured sip port
	if !cfg.RTP || len(cfg.SIPports) == 0 ||
		checkPortsList(sport, dport, cfg.SIPports) {
		return
	}
	// TODO: check if it look like RTP

	// non sip
	// process as RTP
	var endPoints [2]calltr.NetInfo
	var callid [256]byte // temporary callid buffer (rtp pcap)
	isRTP = true
	endPoints[0].SetIP(srcIP)
	endPoints[0].Port = uint16(sport)
	endPoints[0].SetProto(calltr.NProtoUDP)
	endPoints[1].SetIP(dstIP)
	endPoints[1].Port = uint16(dport)
	endPoints[1].SetProto(calltr.NProtoUDP)
	rtpHash := calltr.GetRTPStreamHash()
	match, clen, needed := rtpHash.ProcessPkt(
		endPoints[0], endPoints[1], ts, payload,
		callid[:])
	if needed > clen {
		DBG("returned call-id too big: %d, copied %d\n",
			needed, clen)
	} else if match != calltr.RTPNoMatch {
		rtpMatch = match
		/*
			DBG("rtp packet match %d call: %s\n",
				match, unsafeconv.Str(callid[:clen]))
		*/

		if cfg.WpcapDumpOn && cfg.WpcapDumpRTP {
			/* in the RTP Stream case the CallID is not
			   part of the message (as for SIP) =>
			   path separate key buffer */
			pcapDump = true
			key :=
				sipsp.PField{Offs: 0, Len: sipsp.OffsT(clen)}
			pcapErr := pcapDumper.WriteUDPmsg(srcIP, sport, dstIP, dport,
				key, callid[:clen], ts,
				PcapMsgHdrTimestampF|PcapDumpAppendOnlyF, payload)
			if pcapErr != nil {
				ERR("pcapDumper WriteUDPmsg error %v: "+
					"%s:%d -> %s:%d UDP	payload len: %d\n",
					pcapErr, srcIP, sport, dstIP, dport, len(payload))
			}
		}
	}
	return
}
