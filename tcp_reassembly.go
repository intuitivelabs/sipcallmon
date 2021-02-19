// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"io"
	"net"
	"time"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/sipsp"
)

type SIPStreamState uint8

const (
	SIPStreamInit    SIPStreamState = iota
	SIPStreamParsing                // parsing sip message
	SIPStreamSkipBytes
	SIPStreamSkipCRLF // in-between messages
	SIPStreamParseError
	SIPStreamSyncLost
	SIPStreamFIN
)

var sipStreamState2String = [...]string{
	SIPStreamInit:       "Init",
	SIPStreamParsing:    "Parsing",
	SIPStreamSkipBytes:  "Skip",
	SIPStreamSkipCRLF:   "SkipCRLF",
	SIPStreamParseError: "Error",
	SIPStreamSyncLost:   "SyncLost",
	SIPStreamFIN:        "FIN",
}

func (state SIPStreamState) String() string {
	if int(state) < len(sipStreamState2String) {
		return sipStreamState2String[int(state)]
	}
	return "BUG"
}

type SIPStreamOptions struct {
	Verbose bool
	W       io.Writer // write debug messages here
}

// sip state per stream (uni-directional connection)
type SIPStreamData struct {
	addrBuf [32]byte
	srcIP   net.IP
	dstIP   net.IP
	sport   uint16
	dport   uint16
	lastRcv time.Time
	created time.Time
	rcvd    uint64
	segs    uint64
	oo      uint64 // out of order, dbg

	pmsg   sipsp.PSIPMsg  // message parsing state
	offs   int            // current offset/parsing point in buf[mstart:]
	skip   int            // skip n bytes (e.g. skip body)
	mstart int            // saved current message start in buffer
	bused  int            // how much of buf is used
	state  SIPStreamState // current state
	buf    []byte         // keep not-yet (fully) processed bytes here

	SIPStreamOptions

	resync bool
	ignore bool
	fin    bool
	syn    bool
}

func (s *SIPStreamData) Reset(o *SIPStreamOptions) {
	buf := s.buf
	pmsg := s.pmsg
	var rst SIPStreamData
	*s = rst
	s.buf = buf
	s.pmsg = pmsg
	s.pmsg.Reset()
	if o != nil {
		s.SIPStreamOptions = *o
	}
	s.srcIP = s.addrBuf[:16]
	s.dstIP = s.addrBuf[16:]
}

func (s *SIPStreamData) Init(o *SIPStreamOptions, b []byte) {
	s.Reset(o)
	s.pmsg.Init(nil, nil, nil)
	s.buf = b
}

func (s *SIPStreamData) Process(data []byte) bool {

	/* TODO
	if s.bused == 0 {
		/// buf not used, try to parse data directly maybe it's a full sip packet in it, avoiding copy
	}
	*/
	for len(data) > 0 {
		// TODO: optimize for full buf-> try compacting it here too
		// add as much as possible from data into buf[bused]
		l := copy(s.buf[s.bused:], data)
		data = data[l:]
		s.bused += l
		var err sipsp.ErrorHdr
		var o int
		var dbgl int
		if s.Verbose {
			fmt.Fprintf(s.W, "Process %p pre-loop: state %s, mstart %d, bused %d, skip %d, copied %d bytes\n", s, s.state, s.mstart, s.bused, s.skip, l)
		}
		for err == 0 && s.mstart < s.bused {
			if s.Verbose {
				fmt.Fprintf(s.W, "Process %p loop %d: state %s, mstart %d, bused %d, skip %d\n", s, dbgl, s.state, s.mstart, s.bused, s.skip)
				dbgl++
			}
			switch s.state {
			case SIPStreamParsing:
				o, err = sipsp.ParseSIPMsg(s.buf[s.mstart:s.bused], s.offs,
					&s.pmsg,
					sipsp.SIPMsgSkipBodyF|sipsp.SIPMsgCLenReqF)
				s.offs = o
				if s.Verbose {
					fmt.Fprintf(s.W, "tcp after parsing => %d, %s\n", o, err)
				}
				switch err {
				case 0:
					// stats & dbg
					stats.ok++
					stats.sipTCP++
					if s.pmsg.FL.Request() {
						stats.reqsN++
						stats.method[s.pmsg.FL.MethodNo]++
					} else {
						stats.replsN++
						stats.repl[s.pmsg.FL.Status/100]++
					}
					if s.Verbose {
						fmt.Fprintln(s.W)
					}

					var endPoints [2]calltr.NetInfo
					endPoints[0].SetIP(&s.srcIP)
					endPoints[0].Port = s.sport
					endPoints[0].SetProto(calltr.NProtoTCP)
					endPoints[1].SetIP(&s.dstIP)
					endPoints[1].Port = s.dport
					endPoints[1].SetProto(calltr.NProtoTCP)

					ok := CallTrack(&s.pmsg, &endPoints)
					if ok {
						stats.callTrTCP++
					} else {
						if s.Verbose {
							fmt.Fprintf(s.W, "tcp CallTrack failed\n")
						}
						stats.callTrErrTCP++
					}
					// prepare for new message
					s.mstart += o
					s.offs = 0
					s.skip = int(s.pmsg.PV.CLen.UIVal)
					s.state = SIPStreamSkipBytes
					s.pmsg.Reset()
				case sipsp.ErrHdrMoreBytes:
					// handle skip over body partial body ?
					// m.state = SIPStreamSkipBytes
					// m.start += o
					// m.skip = m.pmsg.PV.CLen.Len - int(m.pmsg.Body.Len)
					// ...

					//... stats ?
				case sipsp.ErrHdrNoCLen:
					stats.errs++
					stats.errsTCP++
					stats.errType[err]++
					stats.bodyErr++
					fmt.Fprintf(s.W, "tcp: missing Content-Length Header: %s\n", err)
					// parse error event
					EventsRing.AddBasic(calltr.EvParseErr,
						s.srcIP, uint16(s.sport), s.dstIP, uint16(s.dport),
						calltr.NProtoTCP,
						s.pmsg.PV.GetCallID().CallID.Get(s.buf[s.mstart:s.bused]),
						[]byte("missing Content-Length"))

					// alternative try with 0 clen ?
					s.state = SIPStreamParseError
					s.mstart += o
					s.pmsg.Reset()
					goto errParse
				default:
					// stats + dbg
					stats.errs++
					stats.errsTCP++
					stats.errType[err]++
					fmt.Fprintf(s.W, "tcp: unexpected error after parsing "+
						"stream sync lost for %p => %s\n", s, err)
					fmt.Fprintf(s.W, "parsed ok:\n%q\n",
						s.buf[s.mstart:s.mstart+o])
					fmt.Fprintln(s.W)
					var l int
					if o+s.mstart < s.bused {
						l = o + s.mstart + 40
						if l > s.bused {
							l = s.bused
						}
						fmt.Fprintf(s.W, "error before:\n%q\n", s.buf[s.mstart+o:l])
					}
					// parse error event
					rep := o
					if rep+s.mstart > s.bused {
						rep = s.bused - s.mstart
					}
					// report first 60 parsed ok chars from the message
					if rep > 60 {
						rep = 60
					}
					EventsRing.AddBasic(calltr.EvParseErr,
						s.srcIP, uint16(s.sport), s.dstIP, uint16(s.dport),
						calltr.NProtoTCP,
						s.pmsg.PV.GetCallID().CallID.Get(s.buf[s.mstart:s.bused]),
						s.buf[s.mstart:s.mstart+rep])
					// actual work
					s.state = SIPStreamParseError
					s.mstart += o
					s.pmsg.Reset()
					goto errParse
				}
			case SIPStreamInit:
				s.state = SIPStreamSkipCRLF
				fallthrough
			case SIPStreamSkipCRLF:
			skipcrlf:
				//advance mstart till first non CRLF char found
				for ; s.mstart < s.bused; s.mstart++ {
					switch s.buf[s.mstart] {
					case '\r', '\n': // do nothing, skip over them
					default:
						s.state = SIPStreamParsing
						break skipcrlf
					}
				}
			case SIPStreamSkipBytes:
				if (s.mstart + s.skip) <= s.bused {
					s.mstart += s.skip
					s.skip = 0
					s.state = SIPStreamSkipCRLF
				} else {
					s.skip -= (s.bused - s.mstart)
					s.mstart = s.bused
				}
			}
		}
		// if we are here => need more bytes
		if s.bused == len(s.buf) {
			// used the entire buf. => make space
			if s.mstart == 0 {
				// not enought space to move message "down"
				// ERROR! Message too big
				goto errTooBig
			}
			if s.Verbose {
				fmt.Fprintf(s.W, "Process %p making space: state %s, mstart %d, bused %d, skip %d\n", s, s.state, s.mstart, s.bused, s.skip)
			}
			copy(s.buf, s.buf[s.mstart:])
			s.bused -= s.mstart
			s.mstart = 0
			if s.Verbose {
				fmt.Fprintf(s.W, "Process %p after space: state %s, mstart %d, bused %d, skip %d\n", s, s.state, s.mstart, s.bused, s.skip)
			}
		}
	}
	if s.Verbose {
		fmt.Fprintf(s.W, "Process %p end: state %s, mstart %d, bused %d, skip %d\n", s, s.state, s.mstart, s.bused, s.skip)
	}
	return true
errTooBig:
	fmt.Fprintf(s.W, "tcp: error message too big on stream %p: %d used,"+
		" msg = %q...\n", s, s.bused, s.buf[:30])
	stats.tooBig++
errParse:
	return false // error
}

// called when n bytes are missing
func (s *SIPStreamData) SkippedBytes(n int) bool {
	// allow only if inside body (SkipBytes mode)
	switch s.state {
	case SIPStreamSkipBytes:
		if s.skip >= n {
			s.skip -= n
			if s.skip == 0 {
				s.state = SIPStreamSkipCRLF
			}
			return true
		} else {
			// try re-covering
			// for now just return ok, if something is wrong
			// we'll get a parsing error later, Process will return false
			// and the stream will be marked as invalud
			s.skip = 0
			return true
		}
	case SIPStreamInit:
		return true // allow skipped packets at the beginning
	case SIPStreamSkipCRLF:
		return true // tricky, allow for now
	case SIPStreamParsing:
		s.state = SIPStreamSyncLost
		s.mstart = 0 // discard everything
		s.bused = 0
		s.pmsg.Reset()
	}
	// TODO: try re-sync, at least in SkipCRLF mode ?
	s.state = SIPStreamSyncLost
	return false
}

// implement gopacket.tcpassembly Stream
func (s *SIPStreamData) Reassembled(bufs []tcpassembly.Reassembly) {

	if s.Verbose {
		fmt.Fprintf(s.W, "%p %s:%d -> %s:%d Reassembled %d bufs, ignore %v\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, len(bufs), s.ignore)
	}
	if s.ignore {
		stats.tcpIgn++
		return
	}
	for i, seg := range bufs {
		if s.Verbose /*&& len(seg.Bytes) > 0*/ {
			fmt.Fprintf(s.W, "%p Reassembled: buf[%d] %q state %d\n", s, i, seg.Bytes, s.state)
		}
		s.syn = s.syn || seg.Start
		s.fin = s.fin || seg.End
		if seg.Start {
			stats.tcpSyn++
		}
		if seg.End {
			stats.tcpFin++
		}
		s.segs++
		s.rcvd += uint64(len(seg.Bytes))
		stats.tcpSegs++
		stats.tcpRcvd += uint64(len(seg.Bytes))
		if s.lastRcv.After(seg.Seen) && s.segs > 1 {
			stats.tcpOutOfOrder++
			// FIXME DBG:
			//if s.Verbose {
			s.oo++ // dbg
			fmt.Fprintf(s.W, "%p %s:%d -> %s:%d %d OO Reassembled, "+
				" after %v (%v ago), lastRcvd %v ago, created %v ago\n",
				s, s.srcIP, s.sport, s.dstIP, s.dport, s.oo,
				s.lastRcv.Sub(seg.Seen), time.Now().Sub(seg.Seen),
				time.Now().Sub(s.lastRcv), time.Now().Sub(s.created))
			//}
		} else {
			s.lastRcv = seg.Seen
		}
		// TODO: if !s.sin => start not seen => ignore ?
		if seg.Skip != 0 {
			stats.tcpMissed++
			if s.segs > 1 {
				stats.tcpMissedBytes += uint64(seg.Skip)
			}
			// else first pkt seen is not syn, it's a prev. estab. conn.
			//   or lessl likely re-ordering at the start
			// TODO: special stat
			if !s.SkippedBytes(seg.Skip) {
				s.ignore = true
				// TODO: free what's possible
				s.buf = nil
				if s.Verbose {
					fmt.Fprintf(s.W, "%p %s:%d -> %s:%d skipped bytes ->DROP CONN %d\n",
						s, s.srcIP, s.sport, s.dstIP, s.dport, seg.Skip)
				}
				break // error - out of sync - ignore stream
			}
			stats.tcpRecovered++
		}
		if !s.Process(seg.Bytes) {
			s.ignore = true
			// TODO: free what's possible
			s.buf = nil
			if s.Verbose {
				fmt.Fprintf(s.W, "%p %s:%d -> %s:%d Process failed for buf %d\n",
					s, s.srcIP, s.sport, s.dstIP, s.dport, i)
			}
			break
		}
	}
}

// implement gopacket.tcpassembly Stream
func (s *SIPStreamData) ReassemblyComplete() {
	if s.Verbose {
		fmt.Fprintf(s.W, "stream %p %s:%d -> %s:%d closing"+
			" (%d bytes %d tcp segs. state %s mstart %d bused %d skip %d)...\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, s.rcvd, s.segs, s.state, s.mstart, s.bused, s.skip)
	}
	// cleanup
	s.pmsg.Reset()
	s.state = SIPStreamFIN
	if s.ignore {
		stats.tcpStreamIgn++
	}
	stats.tcpClosed++
	// free data
	s.ignore = true
	s.buf = nil
}

// implement tcpassembly.Stream

type SIPStreamFactory struct {
	bufSize int
	SIPStreamOptions
}

// implement tcpasembly.StreamFactory
func (f SIPStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	bufSize := f.bufSize
	if bufSize == 0 {
		bufSize = 8192
	}
	// TODO: use a buf cache or at least sync.Pool
	buf := make([]byte, bufSize)
	s := &SIPStreamData{}
	s.Init(&f.SIPStreamOptions, buf)
	if f.Verbose {
		fmt.Fprintf(f.W, "new stream %p, options %+v\n", s, f.SIPStreamOptions)
	}
	// convert from flows to IP:port(s)
	l := copy(s.srcIP, netFlow.Src().Raw())
	s.srcIP = s.srcIP[:l]
	l = copy(s.dstIP, netFlow.Dst().Raw())
	s.dstIP = s.dstIP[:l]
	port := tcpFlow.Src().Raw()
	s.sport = uint16(port[0])<<8 + uint16(port[1])
	port = tcpFlow.Dst().Raw()
	s.dport = uint16(port[0])<<8 + uint16(port[1])
	s.created = time.Now()
	s.lastRcv = s.created
	stats.tcpStreams++
	return s
}
