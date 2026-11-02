package sipcallmon

import (
	"container/list"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/intuitivelabs/counters"
	"github.com/zeebo/xxh3"
)

// RTP sampling for the per call pcap dumps (pcap_dump_rtp_max_pkts).
// Instead of the whole media stream only the first N packets of each
// sampled stream are written. A sampled stream is identified by:
//
//	call-id, src ip:port, dst ip:port, RTP SSRC, RTP payload type
//
// so an SSRC change (B2BUA/SBC re-anchoring, transfer) or a payload type
// change (codec switch after re-INVITE, comfort noise, first DTMF event)
// on the same 5-tuple is sampled again. A re-INVITE / hold that changes
// ports creates a new 5-tuple and is sampled again too.
// A stream that was idle for more than the idle time
// (pcap_dump_rtp_sample_idle) is sampled again when it resumes
// (late start, silence suppression, hold / resume).
// RTCP (rtcp-mux on the same port) is never sampled out: it is low rate and
// carries the end-points' own loss and jitter reports for the whole call.
// Non-RTP payloads on a media port (STUN, DTLS, keep-alives) are sampled
// as one stream per 5-tuple.
//
// The state is bounded: at most rtpSampleMaxCalls calls (LRU) and
// pcap_dump_rtp_max_streams sampled streams per call. A call's state is
// freed once none of its streams saw a packet for the idle time (after the
// call ends calltr removes its RTP streams and no more packets are matched).

// maximum number of calls with sampling state
const rtpSampleMaxCalls = 65536

// RTPSampleRes is the result of RTPSampler.Sample().
type RTPSampleRes uint8

const (
	RTPSampleWrite    RTPSampleRes = iota // write the packet
	RTPSampleSkip                         // stream already sampled
	RTPSampleOverflow                     // too many streams for the call
)

type rtpSampleKind uint8

const (
	rtpSampleRTP rtpSampleKind = iota
	rtpSampleRTCP
	rtpSampleOther // not RTP (STUN, DTLS, keep-alives ...)
)

type rtpSampleKey struct {
	src  netip.AddrPort
	dst  netip.AddrPort
	ssrc uint32
	pt   uint8
	kind rtpSampleKind
}

type rtpSampleStream struct {
	key  rtpSampleKey
	pkts uint32 // packets seen since the sampling (re)started
	last time.Time
}

type rtpSampleCall struct {
	id      uint64 // call-id hash
	last    time.Time
	streams []rtpSampleStream
}

// RTPSampler decides which RTP packets are written in the per call pcaps.
// It is not safe for concurrent use (one per packet processing loop).
type RTPSampler struct {
	maxPkts    uint32
	idle       time.Duration
	maxCalls   int
	maxStreams int

	calls map[uint64]*list.Element // call-id hash -> lru element
	lru   list.List                // *rtpSampleCall, most recent first
}

// NewRTPSampler returns a sampler that writes the first maxPkts packets
// of every stream (maxPkts == 0 means write everything), samples a stream
// again after idle without packets and keeps at most maxStreams sampled
// streams per call.
func NewRTPSampler(maxPkts uint32, idle time.Duration,
	maxStreams int) *RTPSampler {
	s := &RTPSampler{
		maxPkts:    maxPkts,
		idle:       idle,
		maxCalls:   rtpSampleMaxCalls,
		maxStreams: maxStreams,
		calls:      make(map[uint64]*list.Element),
	}
	s.lru.Init()
	return s
}

// Calls returns the number of calls with sampling state.
func (s *RTPSampler) Calls() int {
	return len(s.calls)
}

// rtpSampleClassify returns the sampling kind, SSRC and payload type
// for an UDP payload received on a media port.
func rtpSampleClassify(payload []byte) (rtpSampleKind, uint32, uint8) {
	if len(payload) < 8 || payload[0]>>6 != 2 {
		return rtpSampleOther, 0, 0
	}
	// RFC 5761 4: RTCP packet types 192-223 (second byte with marker bit)
	if payload[1] >= 192 && payload[1] <= 223 {
		return rtpSampleRTCP, binary.BigEndian.Uint32(payload[4:8]), 0
	}
	if len(payload) < 12 {
		return rtpSampleOther, 0, 0
	}
	return rtpSampleRTP, binary.BigEndian.Uint32(payload[8:12]),
		payload[1] & 0x7f
}

func rtpSampleAddrPort(ip net.IP, port int) netip.AddrPort {
	a, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(a.Unmap(), uint16(port))
}

// Sample decides if a packet of the call identified by callid should be
// written. now is the packet time (capture time).
func (s *RTPSampler) Sample(callid []byte, sip net.IP, sport int,
	dip net.IP, dport int, payload []byte, now time.Time) RTPSampleRes {

	if s.maxPkts == 0 {
		return RTPSampleWrite
	}
	kind, ssrc, pt := rtpSampleClassify(payload)
	if kind == rtpSampleRTCP {
		return RTPSampleWrite
	}
	key := rtpSampleKey{
		src:  rtpSampleAddrPort(sip, sport),
		dst:  rtpSampleAddrPort(dip, dport),
		ssrc: ssrc,
		pt:   pt,
		kind: kind,
	}
	call := s.getCall(xxh3.Hash(callid), now)
	var st *rtpSampleStream
	for i := range call.streams {
		if call.streams[i].key == key {
			st = &call.streams[i]
			break
		}
	}
	if st == nil {
		if len(call.streams) >= s.maxStreams {
			call.pruneIdle(now.Add(-s.idle))
			if len(call.streams) >= s.maxStreams {
				return RTPSampleOverflow
			}
		}
		call.streams = append(call.streams, rtpSampleStream{key: key})
		st = &call.streams[len(call.streams)-1]
	} else if now.Sub(st.last) > s.idle {
		st.pkts = 0 // resumed after a pause: sample again
	}
	st.last = now
	if st.pkts >= s.maxPkts {
		return RTPSampleSkip
	}
	st.pkts++
	return RTPSampleWrite
}

// getCall returns the sampling state for a call, creating it if needed,
// marks it as most recently used and frees idle or excess calls.
func (s *RTPSampler) getCall(id uint64, now time.Time) *rtpSampleCall {
	var call *rtpSampleCall
	if e, ok := s.calls[id]; ok {
		call = e.Value.(*rtpSampleCall)
		s.lru.MoveToFront(e)
	} else {
		call = &rtpSampleCall{id: id}
		s.calls[id] = s.lru.PushFront(call)
	}
	call.last = now
	// free calls from the lru tail: idle or over the limit
	limit := now.Add(-s.idle)
	for e := s.lru.Back(); e != nil && e.Value.(*rtpSampleCall) != call; {
		c := e.Value.(*rtpSampleCall)
		if len(s.calls) <= s.maxCalls && !c.last.Before(limit) {
			break
		}
		prev := e.Prev()
		s.lru.Remove(e)
		delete(s.calls, c.id)
		e = prev
	}
	return call
}

// pruneIdle removes the streams with no packets since limit.
func (c *rtpSampleCall) pruneIdle(limit time.Time) {
	n := 0
	for _, st := range c.streams {
		if !st.last.Before(limit) {
			c.streams[n] = st
			n++
		}
	}
	c.streams = c.streams[:n]
}

// rtpDumpSample returns true if the RTP packet should be written to the
// call pcap and updates the pcap dump sampling counters.
func rtpDumpSample(s *RTPSampler, callid []byte, sip net.IP, sport int,
	dip net.IP, dport int, payload []byte, now time.Time) bool {
	res := s.Sample(callid, sip, sport, dip, dport, payload, now)
	if pcapStats != nil {
		switch res {
		case RTPSampleSkip:
			pcapStats.cnts.Inc(pcapStats.hRTPSkipped)
		case RTPSampleOverflow:
			pcapStats.cnts.Inc(pcapStats.hRTPOverflow)
		}
		pcapStats.cnts.Set(pcapStats.hRTPSampleCalls,
			counters.Val(s.Calls()))
	}
	return res == RTPSampleWrite
}
