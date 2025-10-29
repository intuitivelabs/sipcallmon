package sipcallmon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

var ErrIPFIXqosSessionsMax = errors.New("ipfix qos: exceeded maximum" +
	" session number")

const AcmeIPFIXrtpQOS4AddrPortMinLen int = 4 + 4 + 2 + 2 // ipv4

type AcmeIPFIXrtpQOS4AddrPort struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

func (ap AcmeIPFIXrtpQOS4AddrPort) String() string {
	return fmt.Sprintf("%s:%d->%s:%d",
		ap.SrcIP.String(), ap.SrcPort,
		ap.DstIP.String(), ap.DstPort)
}

const AcmeIPFIXrtpQOS4InterimMStreamMinLen int = 1 + // type
	4*AcmeIPFIXrtpQOS4AddrPortMinLen + // (caller up/down addr port + callee )
	1 + 1 + 2 + 1 + 1 + 2 + // (ifslot, ifport, vlan id)   x 2
	4 + 4 + 4 + 4 + // start_s, start_us, stop_s, stop_us
	4 + 4 + 1 + 4 + 4 + 1 + // (ssrc, seq, ptype)  x 2
	4 + // tid
	4*IPFIXvarLenElemMinLen // 4 emtpy strings:  realm x2 + callid x2

// AcmeIPFIXrtpQOS4InterimMStream holds information about both rtp streams
// for a media stream (caller -> callee and calee -> caller). Note that from
// the point of view of addresses, each rtp stream is broken into 2 "legs":
// source -> sbc and sbc -> destination.
type AcmeIPFIXrtpQOS4InterimMStream struct {
	Type      uint8                    // media type
	CallerSBC AcmeIPFIXrtpQOS4AddrPort // caller -> SBC (caller eg1)
	SBCcaller AcmeIPFIXrtpQOS4AddrPort // SBC -> caller (callee leg2)

	CalleeSBC AcmeIPFIXrtpQOS4AddrPort // callee -> SBC (callee leg1)
	SBCcallee AcmeIPFIXrtpQOS4AddrPort // SBC -> callee (caller leg2)

	CallerIfSlot uint8 // interface slot
	CallerIfPort uint8 // interface port
	CallerVlanID uint16

	CalleeIfSlot uint8 // interface slot
	CalleeIfPort uint8 // interface port
	CalleeVlanID uint16

	StartTimeS  uint32 // media start time seconds
	StartTimeUS uint32 // media start time us part

	StopTimeS  uint32 // media stop time seconds
	StopTimeUS uint32 // media stop time us part

	CallerSSRC uint32
	CallerSeq  uint32
	CallerPT   uint8 // rtp payload type

	CalleeSSRC uint32
	CalleeSeq  uint32
	CalleePT   uint8 // rtp payload type

	Tid uint32

	CallerRealm IPFIXvarLenElem
	CalleeRealm IPFIXvarLenElem

	CallerCallID IPFIXvarLenElem
	CalleeCallID IPFIXvarLenElem
}

const AcmeIPFIXrtpStatsLen int = 5 * 4

// AcmeIPFIXrtpStats holds rtp qos stats
type AcmeIPFIXrtpStats struct {
	Bytes     uint32
	Pkts      uint32
	LostPkts  uint32
	JitterAvg uint32
	JitterMax uint32
}

const AcmeIPFIXrtcpStatsLen int = AcmeIPFIXrtpStatsLen + 2*4

type AcmeIPFIXrtcpStats struct {
	AcmeIPFIXrtpStats
	LatencyAvg uint32
	LatencyMax uint32
}

const AcmeIPFIXrtcpStats2Len int = 2 * 4

// AcmeIPFIXrtcpStats2 seems to contain computed quality
// assesments for voice or video. They seem to be multiplied by 100.
// Notes:
// MOS is usally calculated from the R-value:
// MOS=1+0.035R+R(R−60)(100−R)×7/10^6
// Max MOS for G.711: ~4.5, G.729: ~4.0, G.723.1: ~3.6
type AcmeIPFIXrtcpStats2 struct {
	Rvalue uint32 // r-value or r-factor: voice quality from 0-100 * 100(?)
	MOS    uint32 // mean opinion score from 1-5 * 100 (?)
}

const AcmeIPFIXrtQOSstatsLen int = AcmeIPFIXrtpStatsLen +
	AcmeIPFIXrtcpStatsLen + AcmeIPFIXrtcpStats2Len

type AcmeIPFIXrtpQOSstats struct {
	RTP   AcmeIPFIXrtpStats
	RTCP  AcmeIPFIXrtcpStats
	RTCP2 AcmeIPFIXrtcpStats2 // ?
}

const AcmeIPFIXrtQOS4InterimMStreamInfoMinLen int = 2*AcmeIPFIXrtQOSstatsLen +
	AcmeIPFIXrtpQOS4InterimMStreamMinLen

type AcmeIPFIXrtpQOS4InterimMStreamInfo struct {
	StatsA  AcmeIPFIXrtpQOSstats
	StatsB  AcmeIPFIXrtpQOSstats
	MStream AcmeIPFIXrtpQOS4InterimMStream
}

// String returns a string version of the
// AcmeIPFIXrtpQOS4InterimMStreamInfo contents.
func (v AcmeIPFIXrtpQOS4InterimMStreamInfo) String() string {
	ms := v.MStream
	return fmt.Sprintf(
		"Type=%d "+
			"Caller:[%s SBC %s] "+
			"Callee:[%s SBC %s] "+
			"CallerIf=%d/%d VLAN=%d CalleeIf=%d/%d VLAN=%d "+
			"CallerSSRC=%08x CalleeSSRC=%08x "+
			"CallerSeq=%08x CallerPType=%08x "+
			"CalleeSeq=%08x CalleePType=%08x "+
			"Tid=%08x "+
			"Start=%v Stop=%v "+
			"StatsA[Pkts=%d Lost=%d JitAvg=%d JitMax=%d LatAvg=%d"+
			" LatMax=%d jitAvg=%d jitMax=%d R=%d MOS=%d] "+
			"StatsB[Pkts=%d Lost=%d JitAvg=%d JitMax=%d LatAvg=%d"+
			" LatMax=%d jitAvg=%d jitMax=%d R=%d MOS=%d] "+
			"CallerRealm=%q CalleeRealm=%q CallerCallID=%q CalleeCallID=%q",
		ms.Type,
		ms.CallerSBC, ms.SBCcallee,
		ms.CalleeSBC, ms.SBCcaller,
		ms.CallerIfSlot, ms.CallerIfPort, ms.CallerVlanID,
		ms.CalleeIfSlot, ms.CalleeIfPort, ms.CalleeVlanID,
		ms.CallerSSRC, ms.CalleeSSRC,
		ms.CallerSeq, ms.CallerPT,
		ms.CalleeSeq, ms.CalleePT,
		ms.Tid,

		time.Unix(int64(ms.StartTimeS), int64(ms.StartTimeUS)*1000).Format(
			"2006-01-02_15:04:05"),
		time.Unix(int64(ms.StopTimeS), int64(ms.StopTimeUS)*1000).Format(
			"2006-01-02_15:04:05"),

		v.StatsA.RTP.Pkts, v.StatsA.RTP.LostPkts, v.StatsA.RTP.JitterAvg,
		v.StatsA.RTP.JitterMax,
		v.StatsA.RTCP.LatencyAvg, v.StatsA.RTCP.LatencyMax,
		v.StatsA.RTCP.JitterAvg, v.StatsA.RTCP.JitterMax,
		v.StatsA.RTCP2.Rvalue, v.StatsA.RTCP2.MOS,

		v.StatsB.RTP.Pkts, v.StatsB.RTP.LostPkts, v.StatsB.RTP.JitterAvg,
		v.StatsB.RTP.JitterMax,
		v.StatsB.RTCP.LatencyAvg, v.StatsB.RTCP.LatencyMax,
		v.StatsB.RTCP.JitterAvg, v.StatsB.RTCP.JitterMax,
		v.StatsB.RTCP2.Rvalue, v.StatsB.RTCP2.MOS,

		ms.CallerRealm, ms.CalleeRealm,
		ms.CallerCallID, ms.CalleeCallID,
	)
}

const AcmeIPFIXrtpQOS4InterimSetMinLen = 0 +
	AcmeIPFIXrtQOS4InterimMStreamInfoMinLen

type AcmeIPFIXrtpQOS4InterimSet struct {
	MStreams [10]AcmeIPFIXrtpQOS4InterimMStreamInfo // variable streams
	No       int                                    // no. of filled streams
}

// ParseAcmeIPFIXrtpQOS4AddrPort parses one AcmeIPFIXrtpQOS4AddrPort structure
// from buf[offset:].
// It returns  a filled AcmeIPFIXrtpQOS4AddrPort structure, the next offset after
// parsing it, how much bigger the buffer needs to be if it was
// too small and ErrIPFIXmoreBytes if not enough data was available.
func ParseAcmeIPFIXrtpQOS4AddrPort(buf []byte, offset int,
) (v AcmeIPFIXrtpQOS4AddrPort, next int, need int, err error) {
	if len(buf[offset:]) < AcmeIPFIXrtpQOS4AddrPortMinLen {
		return v, offset,
			AcmeIPFIXrtpQOS4AddrPortMinLen - len(buf[offset:]),
			ErrIPFIXmoreBytes
	}

	p := offset
	v.SrcIP = buf[p : p+4]
	p += 4
	v.DstIP = buf[p : p+4]
	p += 4
	v.SrcPort = binary.BigEndian.Uint16(buf[p:])
	p += 2
	v.DstPort = binary.BigEndian.Uint16(buf[p:])
	p += 2

	return v, p, 0, nil
}

// ParseAcmeIPFIXrtpQOS4InterimMStream parses one AcmeIPFIXrtpQOS4InterimMStream
// from buf starting at offs.
// It returns a filled AcmeIPFIXrtpQOS4InterimMStream structure (with slices
// pointing into buf), the offset after the parsed data, how much more bytes
// the buffer needs if the passed buffer was to small and an error.
//
//	On success, err is nil and 'next' is the position after
//
// the parsed data. If the buffer was too short, it returns ErrIPFIXmoreBytes
// and the number of additional bytes required.
func ParseAcmeIPFIXrtpQOS4InterimMStream(
	buf []byte, offs int,
) (v AcmeIPFIXrtpQOS4InterimMStream, next int, need int, err error) {
	if len(buf[offs:]) < AcmeIPFIXrtpQOS4InterimMStreamMinLen {
		return v, offs,
			AcmeIPFIXrtpQOS4InterimMStreamMinLen - len(buf[offs:]),
			ErrIPFIXmoreBytes
	}
	p := offs

	// 1. Type
	v.Type = buf[p]
	p++

	// 2–5. 4 addr/port blocks
	if v.CallerSBC, p, need, err =
		ParseAcmeIPFIXrtpQOS4AddrPort(buf, p); err != nil {
		BUG("unexpected min check failed: len(buf)=%d len(buf[%d:])=%d"+
			" (min %d) pos %d => need %d:\n",
			len(buf), offs, len(buf[offs:]),
			AcmeIPFIXrtpQOS4InterimMStreamMinLen, p, need)
		return v, p, need, err
	}
	if v.SBCcaller, p, need, err =
		ParseAcmeIPFIXrtpQOS4AddrPort(buf, p); err != nil {
		BUG("unexpected min check failed: len(buf)=%d len(buf[%d:])=%d"+
			" (min %d) pos %d => need %d:\n",
			len(buf), offs, len(buf[offs:]),
			AcmeIPFIXrtpQOS4InterimMStreamMinLen, p, need)
		return v, p, need, err
	}
	if v.CalleeSBC, p, need, err =
		ParseAcmeIPFIXrtpQOS4AddrPort(buf, p); err != nil {
		BUG("unexpected min check failed: len(buf)=%d len(buf[%d:])=%d"+
			" (min %d) pos %d => need %d:\n",
			len(buf), offs, len(buf[offs:]),
			AcmeIPFIXrtpQOS4InterimMStreamMinLen, p, need)
		return v, p, need, err
	}
	if v.SBCcallee, p, need, err =
		ParseAcmeIPFIXrtpQOS4AddrPort(buf, p); err != nil {
		BUG("unexpected min check failed: len(buf)=%d len(buf[%d:])=%d"+
			" (min %d) pos %d => need %d:\n",
			len(buf), offs, len(buf[offs:]),
			AcmeIPFIXrtpQOS4InterimMStreamMinLen, p, need)
		return v, p, need, err
	}

	// 6. Caller interface info
	v.CallerIfSlot = buf[p]
	v.CallerIfPort = buf[p+1]
	v.CallerVlanID = binary.BigEndian.Uint16(buf[p+2:])
	p += 4

	// 7. Callee interface info
	v.CalleeIfSlot = buf[p]
	v.CalleeIfPort = buf[p+1]
	v.CalleeVlanID = binary.BigEndian.Uint16(buf[p+2:])
	p += 4

	// 8. Times
	v.StartTimeS = binary.BigEndian.Uint32(buf[p:])
	v.StartTimeUS = binary.BigEndian.Uint32(buf[p+4:])
	v.StopTimeS = binary.BigEndian.Uint32(buf[p+8:])
	v.StopTimeUS = binary.BigEndian.Uint32(buf[p+12:])
	p += 16

	// 9. Caller RTP info
	v.CallerSSRC = binary.BigEndian.Uint32(buf[p:])
	v.CallerSeq = binary.BigEndian.Uint32(buf[p+4:])
	v.CallerPT = buf[p+8]
	p += 9

	// 10. Callee RTP info
	v.CalleeSSRC = binary.BigEndian.Uint32(buf[p:])
	v.CalleeSeq = binary.BigEndian.Uint32(buf[p+4:])
	v.CalleePT = buf[p+8]
	p += 9

	// 11. Tid
	v.Tid = binary.BigEndian.Uint32(buf[p:])
	p += 4

	// 12. Four variable-length fields
	v.CallerRealm, p, need, err = ParseIPFIXvarLenElem(buf, p)
	if err != nil {
		return v, p, need, err
	}
	v.CalleeRealm, p, need, err = ParseIPFIXvarLenElem(buf, p)
	if err != nil {
		return v, p, need, err
	}
	v.CallerCallID, p, need, err = ParseIPFIXvarLenElem(buf, p)
	if err != nil {
		return v, p, need, err
	}
	v.CalleeCallID, p, need, err = ParseIPFIXvarLenElem(buf, p)
	if err != nil {
		return v, p, need, err
	}

	return v, p, 0, nil

}

// ParseAcmeIPFIXrtpStats parses an AcmeIPFIXrtpStats structure from buf[offset:].
// It returns the next offset, how many bytes are needed
// if incomplete, and an error (nil or ErrIPFIXmoreBytes).
func ParseAcmeIPFIXrtpStats(
	buf []byte, offset int,
) (v AcmeIPFIXrtpStats, next int, need int, err error) {
	const l = AcmeIPFIXrtpStatsLen
	if len(buf[offset:]) < l {
		return v, offset, l - len(buf[offset:]), ErrIPFIXmoreBytes
	}
	p := offset
	v.Bytes = binary.BigEndian.Uint32(buf[p:])
	v.Pkts = binary.BigEndian.Uint32(buf[p+4:])
	v.LostPkts = binary.BigEndian.Uint32(buf[p+8:])
	v.JitterAvg = binary.BigEndian.Uint32(buf[p+12:])
	v.JitterMax = binary.BigEndian.Uint32(buf[p+16:])
	p += l
	return v, p, 0, nil
}

// ParseAcmeIPFIXrtcpStats parses an AcmeIPFIXrtcpStats structure from buf[offset:].
// It returns the next offset, how many bytes are needed
// if incomplete, and an error (nil or ErrIPFIXmoreBytes).
func ParseAcmeIPFIXrtcpStats(
	buf []byte, offset int,
) (v AcmeIPFIXrtcpStats, next int, need int, err error) {
	const l = AcmeIPFIXrtcpStatsLen
	if len(buf[offset:]) < l {
		return v, offset, l - len(buf[offset:]), ErrIPFIXmoreBytes
	}

	p := offset
	// Parse embedded RTP stats first
	v.Bytes = binary.BigEndian.Uint32(buf[p:])
	v.Pkts = binary.BigEndian.Uint32(buf[p+4:])
	v.LostPkts = binary.BigEndian.Uint32(buf[p+8:])
	v.JitterAvg = binary.BigEndian.Uint32(buf[p+12:])
	v.JitterMax = binary.BigEndian.Uint32(buf[p+16:])
	// Parse RTCP-specific fields
	v.LatencyAvg = binary.BigEndian.Uint32(buf[p+20:])
	v.LatencyMax = binary.BigEndian.Uint32(buf[p+24:])
	p += l

	return v, p, 0, nil
}

// ParseAcmeIPFIXrtcpStats2 parses an AcmeIPFIXrtcpStats2 structure from buf[offset:].
// It performs no allocations and returns the next offset, how many bytes are needed
// if incomplete, and an error (nil or ErrIPFIXmoreBytes).
func ParseAcmeIPFIXrtcpStats2(
	buf []byte, offset int,
) (v AcmeIPFIXrtcpStats2, next int, need int, err error) {
	const l = AcmeIPFIXrtcpStats2Len
	if len(buf[offset:]) < l {
		return v, offset, l - len(buf[offset:]), ErrIPFIXmoreBytes
	}
	p := offset
	v.Rvalue = binary.BigEndian.Uint32(buf[p:])
	v.MOS = binary.BigEndian.Uint32(buf[p+4:])
	p += l
	return v, p, 0, nil
}

// ParseAcmeIPFIXrtpQOSstats parses a full RTP QoS stats block (RTP + RTCP + RTCP2).
func ParseAcmeIPFIXrtpQOSstats(
	buf []byte, offset int,
) (v AcmeIPFIXrtpQOSstats, next int, need int, err error) {
	const l = AcmeIPFIXrtQOSstatsLen
	if len(buf[offset:]) < l {
		return v, offset, l - len(buf[offset:]), ErrIPFIXmoreBytes
	}

	v.RTP, offset, _, _ = ParseAcmeIPFIXrtpStats(buf, offset)
	v.RTCP, offset, _, _ = ParseAcmeIPFIXrtcpStats(buf, offset)
	v.RTCP2, offset, need, err = ParseAcmeIPFIXrtcpStats2(buf, offset)

	return v, offset, need, err
}

// ParseAcmeIPFIXrtpQOS4InterimMStreamInfo parses a full multi-stream
// RTP QoS record.
// Layout:
//
//	[StatsA][StatsB][MStream]
//
// Returns a fully filled structure, the offset after the parsed data,
// missing byte count if incomplete, and error (nil or ErrIPFIXmoreBytes).
func ParseAcmeIPFIXrtpQOS4InterimMStreamInfo(
	buf []byte, offset int,
) (v AcmeIPFIXrtpQOS4InterimMStreamInfo, next int, need int, err error) {
	const l = AcmeIPFIXrtQOS4InterimMStreamInfoMinLen
	if len(buf[offset:]) < l {
		return v, offset, l - len(buf[offset:]), ErrIPFIXmoreBytes
	}
	// Parse StatsA
	v.StatsA, offset, need, err = ParseAcmeIPFIXrtpQOSstats(buf, offset)
	if err != nil {
		return v, offset, need, err
	}

	// Parse StatsB
	v.StatsB, offset, need, err = ParseAcmeIPFIXrtpQOSstats(buf, offset)
	if err != nil {
		return v, offset, need, err
	}

	// Parse main stream structure
	v.MStream, offset, need, err =
		ParseAcmeIPFIXrtpQOS4InterimMStream(buf, offset)

	return v, offset, need, err
}

// ParseAcmeIPFIXrtpQOS4InterimSet parses one
// AcmeIPFIXrtpQOS4InterimSet structure containing a variable number of
// AcmeIPFIXrtpQOS4InterimMStreamInfo entries.
//
// It fills the MStreams array in order, and returns:
//   - a fully or partially filled AcmeIPFIXrtpQOS4InterimSet
//   - the next offset (after the last parsed stream)
//   - the number of missing bytes if the buffer was too small
//   - an error (nil or ErrIPFIXmoreBytes)
//
// The buffer is expected to contain one or more complete stream info blocks
// laid out sequentially. Parsing stops when the buffer is fully consumed or
// when an incomplete block is encountered.
func ParseAcmeIPFIXrtpQOS4InterimSet(
	buf []byte, offset int,
) (v AcmeIPFIXrtpQOS4InterimSet, next int, need int, err error) {
	next = offset

	for len(buf[next:]) > 0 {
		if v.No >= len(v.MStreams) {
			// stop if the internal array is full; ignore extra streams
			return v, next, 0, ErrIPFIXqosSessionsMax
		}

		ms, n, needBytes, e :=
			ParseAcmeIPFIXrtpQOS4InterimMStreamInfo(buf, next)
		if e != nil {
			// parsing failure
			return v, next, needBytes, e
		}

		v.MStreams[v.No] = ms
		v.No++
		next = n

		/*
			// if buffer exactly ends here stop cleanly
			if next >= len(buf) {
				break
			}
		*/
	}

	return v, next, 0, nil
}
