package sipcallmon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

var (
	tAIP = net.ParseIP("192.0.2.1")
	tBIP = net.ParseIP("198.51.100.2")
	tT0  = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
)

const (
	tIdle       = 10 * time.Second
	tMaxStreams = 32
)

func tSampler(maxPkts uint32) *RTPSampler {
	return NewRTPSampler(maxPkts, tIdle, tMaxStreams)
}

func tRTP(pt uint8, ssrc uint32, seq uint16) []byte {
	b := make([]byte, 12+160)
	b[0] = 0x80
	b[1] = pt
	binary.BigEndian.PutUint16(b[2:], seq)
	binary.BigEndian.PutUint32(b[8:], ssrc)
	return b
}

func tRTCP(ssrc uint32) []byte {
	b := make([]byte, 28)
	b[0] = 0x81
	b[1] = 201 // RR
	binary.BigEndian.PutUint32(b[4:], ssrc)
	return b
}

// tSend feeds n packets 20 ms apart starting at t and returns the number
// of packets that would be written and the time after the last packet.
func tSend(s *RTPSampler, cid string, sp, dp int, n int, t time.Time,
	pkt func(i int) []byte) (int, time.Time) {
	w := 0
	for i := 0; i < n; i++ {
		if s.Sample([]byte(cid), tAIP, sp, tBIP, dp, pkt(i), t) ==
			RTPSampleWrite {
			w++
		}
		t = t.Add(20 * time.Millisecond)
	}
	return w, t
}

func TestRTPSampleFirstN(t *testing.T) {
	s := tSampler(10)
	pcmu := func(i int) []byte { return tRTP(0, 0x1111, uint16(i)) }
	if w, _ := tSend(s, "c1", 4000, 5000, 3000, tT0, pcmu); w != 10 {
		t.Fatalf("written %d packets of 3000, expected 10", w)
	}
	// other direction is another stream
	w := 0
	for i := 0; i < 50; i++ {
		if s.Sample([]byte("c1"), tBIP, 5000, tAIP, 4000,
			tRTP(0, 0x2222, uint16(i)), tT0) == RTPSampleWrite {
			w++
		}
	}
	if w != 10 {
		t.Fatalf("reverse direction: written %d, expected 10", w)
	}
	// same 5-tuple in another call (port reuse) is sampled again
	if w, _ := tSend(s, "c2", 4000, 5000, 20, tT0, pcmu); w != 10 {
		t.Fatalf("other call: written %d, expected 10", w)
	}
}

func TestRTPSampleAll(t *testing.T) {
	s := tSampler(0)
	w, _ := tSend(s, "c1", 4000, 5000, 500, tT0,
		func(i int) []byte { return tRTP(8, 1, uint16(i)) })
	if w != 500 || s.Calls() != 0 {
		t.Fatalf("max 0: written %d of 500, %d calls with state", w,
			s.Calls())
	}
}

func TestRTPSampleSSRCAndPT(t *testing.T) {
	s := tSampler(5)
	// 100 PCMU, then SSRC change (SBC re-anchoring), then
	// telephone-event (101), then CN (13), all on the same 5-tuple
	w, tn := tSend(s, "c", 4000, 5000, 100, tT0,
		func(i int) []byte { return tRTP(0, 0xa, uint16(i)) })
	w2, tn := tSend(s, "c", 4000, 5000, 100, tn,
		func(i int) []byte { return tRTP(0, 0xb, uint16(i)) })
	w3, tn := tSend(s, "c", 4000, 5000, 20, tn,
		func(i int) []byte { return tRTP(101|0x80, 0xb, uint16(i)) })
	w4, tn := tSend(s, "c", 4000, 5000, 20, tn,
		func(i int) []byte { return tRTP(13, 0xb, uint16(i)) })
	// back to PCMU on the new SSRC: already sampled
	w5, _ := tSend(s, "c", 4000, 5000, 100, tn,
		func(i int) []byte { return tRTP(0, 0xb, uint16(i)) })
	if w != 5 || w2 != 5 || w3 != 5 || w4 != 5 || w5 != 0 {
		t.Fatalf("written %d %d %d %d %d, expected 5 5 5 5 0",
			w, w2, w3, w4, w5)
	}
}

func TestRTPSampleRTCPAndOther(t *testing.T) {
	s := tSampler(3)
	// rtcp-mux on the media port: never sampled out
	w, _ := tSend(s, "c", 4000, 5000, 40, tT0,
		func(i int) []byte { return tRTCP(0xa) })
	if w != 40 {
		t.Fatalf("rtcp: written %d of 40", w)
	}
	// non RTP (STUN binding, short packets): one stream per 5-tuple
	stun := func(i int) []byte {
		b := make([]byte, 20)
		b[1] = 0x01
		return b
	}
	short := func(i int) []byte { return []byte{0x80, 0, 0, 1, 0, 0, 0, 0} }
	w, tn := tSend(s, "c", 4000, 5000, 10, tT0, stun)
	w2, _ := tSend(s, "c", 4000, 5000, 10, tn, short)
	if w+w2 != 3 {
		t.Fatalf("non rtp: written %d+%d, expected 3", w, w2)
	}
}

func TestRTPSampleIdleResume(t *testing.T) {
	s := tSampler(10)
	pkt := func(i int) []byte { return tRTP(0, 1, uint16(i)) }
	w, tn := tSend(s, "c", 4000, 5000, 100, tT0, pkt)
	// silence shorter than the idle time: no new sample
	w2, tn := tSend(s, "c", 4000, 5000, 100, tn.Add(5*time.Second), pkt)
	// hold / long silence: sampled again on resume
	w3, _ := tSend(s, "c", 4000, 5000, 100, tn.Add(tIdle+time.Second),
		pkt)
	if w != 10 || w2 != 0 || w3 != 10 {
		t.Fatalf("written %d %d %d, expected 10 0 10", w, w2, w3)
	}
}

func TestRTPSampleStreamLimit(t *testing.T) {
	s := tSampler(2)
	tn := tT0
	var res []RTPSampleRes
	// a source changing SSRC on every packet must not defeat the sampling
	for i := 0; i < tMaxStreams+10; i++ {
		res = append(res, s.Sample([]byte("c"), tAIP, 4000, tBIP, 5000,
			tRTP(0, uint32(i), 1), tn))
		tn = tn.Add(time.Millisecond)
	}
	for i, r := range res {
		exp := RTPSampleWrite
		if i >= tMaxStreams {
			exp = RTPSampleOverflow
		}
		if r != exp {
			t.Fatalf("ssrc %d: result %d, expected %d", i, r, exp)
		}
	}
	// after the idle time the old streams are pruned
	tn = tn.Add(tIdle + time.Second)
	if r := s.Sample([]byte("c"), tAIP, 4000, tBIP, 5000,
		tRTP(0, 0xffff, 1), tn); r != RTPSampleWrite {
		t.Fatalf("after idle: result %d, expected write", r)
	}
	if n := len(s.calls); n != 1 {
		t.Fatalf("%d calls, expected 1", n)
	}
}

func TestRTPSampleCallState(t *testing.T) {
	s := tSampler(10)
	s.maxCalls = 4
	pkt := func(i int) []byte { return tRTP(0, 1, uint16(i)) }
	for _, cid := range []string{"a", "b", "c", "d", "e", "f"} {
		tSend(s, cid, 4000, 5000, 3, tT0, pkt)
	}
	if s.Calls() != 4 || s.lru.Len() != 4 {
		t.Fatalf("%d calls (lru %d), expected the limit 4", s.Calls(),
			s.lru.Len())
	}
	// the least recently used calls were dropped
	for _, cid := range []string{"a", "b"} {
		if w, _ := tSend(s, cid, 4000, 5000, 1, tT0, pkt); w != 1 {
			t.Fatalf("evicted call %s not sampled again", cid)
		}
	}
	// a packet after the idle time frees every other call
	tSend(s, "z", 4000, 5000, 1, tT0.Add(tIdle+time.Second), pkt)
	if s.Calls() != 1 || s.lru.Len() != 1 {
		t.Fatalf("%d calls (lru %d) after idle, expected 1", s.Calls(),
			s.lru.Len())
	}
}

func TestRTPSampleIPv4Mapped(t *testing.T) {
	s := tSampler(1)
	pkt := tRTP(0, 1, 1)
	if s.Sample([]byte("c"), tAIP.To16(), 4000, tBIP.To16(), 5000, pkt,
		tT0) != RTPSampleWrite ||
		s.Sample([]byte("c"), tAIP.To4(), 4000, tBIP.To4(), 5000, pkt,
			tT0) != RTPSampleSkip {
		t.Fatalf("4-byte and 16-byte forms of the same IPv4 address" +
			" must be the same stream")
	}
}

func TestRTPSampleCfgCheck(t *testing.T) {
	cfg := defaultConfigVals
	cfg.BPF = "udp"
	cfg.WpcapDumpOn = true
	cfg.WpcapDir = "/tmp"
	cfg.WpcapRTPMaxN = -1
	if err := CfgCheck(&cfg); err == nil {
		t.Fatalf("negative pcap_dump_rtp_max_pkts accepted")
	}
	cfg.WpcapRTPMaxN = 0
	if err := CfgCheck(&cfg); err != nil {
		t.Fatalf("pcap_dump_rtp_max_pkts 0 rejected: %s", err)
	}
	cfg.WpcapRTPIdle = 0
	if err := CfgCheck(&cfg); err == nil {
		t.Fatalf("pcap_dump_rtp_sample_idle 0 accepted")
	}
	cfg.WpcapRTPIdle = time.Second
	cfg.WpcapRTPStrms = 0
	if err := CfgCheck(&cfg); err == nil {
		t.Fatalf("pcap_dump_rtp_max_streams 0 accepted")
	}
}

func TestRTPSampleConfigured(t *testing.T) {
	// shorter idle time: a 5 s pause is enough to sample again
	s := NewRTPSampler(3, 2*time.Second, 2)
	pkt := func(i int) []byte { return tRTP(0, 1, uint16(i)) }
	w, tn := tSend(s, "c", 4000, 5000, 20, tT0, pkt)
	w2, tn := tSend(s, "c", 4000, 5000, 20, tn.Add(time.Second), pkt)
	w3, tn := tSend(s, "c", 4000, 5000, 20, tn.Add(5*time.Second), pkt)
	if w != 3 || w2 != 0 || w3 != 3 {
		t.Fatalf("idle 2s: written %d %d %d, expected 3 0 3", w, w2, w3)
	}
	// stream cap 2: the third SSRC is not written
	var res []RTPSampleRes
	for ssrc := uint32(2); ssrc <= 3; ssrc++ {
		res = append(res, s.Sample([]byte("c"), tAIP, 4000, tBIP, 5000,
			tRTP(0, ssrc, 1), tn))
	}
	if res[0] != RTPSampleWrite || res[1] != RTPSampleOverflow {
		t.Fatalf("max streams 2: results %v, expected [write overflow]", res)
	}
}
