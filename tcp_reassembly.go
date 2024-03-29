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
	"io/ioutil"
	"net"
	"time"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/slog"
	"github.com/intuitivelabs/timestamp"
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
	bufSize    int
	bufMaxSize int
	Verbose    bool
	W          io.Writer // write debug messages here
	WSports    []uint16  // web socket ports list
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

	pmsg    sipsp.PSIPMsg  // message parsing state
	siphdrs [100]sipsp.Hdr // max 100 parsed sip headers
	offs    int            // current offset/parsing point in buf[mstart:]
	skip    int            // skip n bytes (e.g. skip body)
	mstart  int            // saved current message start in buffer
	bused   int            // how much of buf is used
	state   SIPStreamState // current state
	buf     []byte         // keep not-yet (fully) processed bytes here

	SIPStreamOptions

	resync bool
	ignore bool
	fin    bool
	syn    bool
}

func (s *SIPStreamData) Reset(o *SIPStreamOptions) {
	buf := s.buf
	s.pmsg.Reset()
	pmsg := s.pmsg
	var rst SIPStreamData
	*s = rst
	s.buf = buf
	s.pmsg = pmsg
	if o != nil {
		s.SIPStreamOptions = *o
	}
	s.srcIP = s.addrBuf[:16]
	s.dstIP = s.addrBuf[16:]
}

func (s *SIPStreamData) Init(o *SIPStreamOptions, b []byte) {
	s.Reset(o)
	s.pmsg.Init(nil, s.siphdrs[:], nil)
	s.buf = b
}

func (s *SIPStreamData) FinishInit() {
	if s.buf == nil {
		sz := s.bufSize
		if sz == 0 {
			sz = 8192
		}
		s.buf = make([]byte, sz) // TODO sync.Pool or alloc
	}
}

// growBuf tries to grow the internal buffer, up to s.bufMaxSize.
// Returns true on success, false on error (cannot grow, max size).
func (s *SIPStreamData) growBuf() bool {
	if len(s.buf) < s.bufMaxSize {
		sz := 2 * len(s.buf)
		if sz > s.bufMaxSize {
			sz = s.bufMaxSize
		}
		b := make([]byte, sz) // TODO: sync.Pool or alloc
		// copy only the used part
		copy(b, s.buf[s.mstart:s.bused])
		s.buf = b // TODO: if sync.Pool or alloc put/free prev s.buf
		s.bused -= s.mstart
		s.mstart = 0
		// TODO: stats: inc tcpBufGrow, set tcpBufMax.
		return true
	}
	return false
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
		if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
			Plog.LogMux(s.W, true, slog.LDBG,
				"Process %p pre-loop: state %s, mstart %d,"+
					" bused %d, skip %d, copied %d bytes\n",
				s, s.state, s.mstart, s.bused, s.skip, l)
		}
		for err == 0 && s.mstart < s.bused {
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"Process %p loop %d: state %s, mstart %d,"+
						" bused %d, skip %d\n",
					s, dbgl, s.state, s.mstart, s.bused, s.skip)
				dbgl++
			}
			switch s.state {
			case SIPStreamParsing:
				o, err = sipsp.ParseSIPMsg(s.buf[s.mstart:s.bused], s.offs,
					&s.pmsg,
					sipsp.SIPMsgSkipBodyF|sipsp.SIPMsgCLenReqF)
				s.offs = o
				if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
					Plog.LogMux(s.W, true, slog.LDBG,
						"tcp after parsing => %d, %s\n", o, err)
				}
				switch err {
				case 0:
					// stats & dbg
					stats.Inc(sCnts.ok)
					stats.Inc(sCnts.sipTCP)
					if s.pmsg.FL.Request() {
						stats.Inc(sCnts.reqsN)
						stats.Inc(sCnts.method[s.pmsg.FL.MethodNo])
					} else {
						stats.Inc(sCnts.replsN)
						if s.pmsg.FL.Status < 1000 {
							stats.Inc(sCnts.repl[s.pmsg.FL.Status/100])
						}
					}
					if s.Verbose {
						fmt.Fprintln(s.W)
					}

					var endPoints [2]calltr.NetInfo
					endPoints[0].SetIP(s.srcIP)
					endPoints[0].Port = s.sport
					endPoints[0].SetProto(calltr.NProtoTCP)
					endPoints[1].SetIP(s.dstIP)
					endPoints[1].Port = s.dport
					endPoints[1].SetProto(calltr.NProtoTCP)

					ok := CallTrack(&s.pmsg, endPoints)
					if ok {
						stats.Inc(sCnts.callTrTCP)
					} else {
						if s.Verbose &&
							(Plog.L(slog.LERR) || s.W != ioutil.Discard) {
							Plog.LogMux(s.W, true, slog.LERR,
								"ERROR: tcp CallTrack failed\n")
						}
						stats.Inc(sCnts.callTrErrTCP)
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
					stats.Inc(sCnts.errs)
					stats.Inc(sCnts.errsTCP)
					stats.Inc(sCnts.errType[err])
					stats.Inc(sCnts.bodyErr)
					if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
						Plog.LogMux(s.W, true, slog.LNOTICE,
							"tcp: missing Content-Length Header: %s\n", err)
					}
					// parse error event
					pktErrEvHandler(calltr.EvParseErr,
						s.srcIP, int(s.sport), s.dstIP, int(s.dport),
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
					stats.Inc(sCnts.errs)
					stats.Inc(sCnts.errsTCP)
					stats.Inc(sCnts.errType[err])
					if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
						Plog.LogMux(s.W, true, slog.LNOTICE,
							"tcp: unexpected error after parsing "+
								"stream sync lost for %p => %s\n", s, err)
						Plog.LogMux(s.W, true, slog.LNOTICE,
							"parsed ok:\n%q\n",
							s.buf[s.mstart:s.mstart+o])
						fmt.Fprintln(s.W)
					} else if err == sipsp.ErrHdrBug ||
						err == sipsp.ErrConvBug {
						// show parsing bug always
						Plog.BUG("unexpected error after parsing => %s ,"+
							" parsed ok:\n%q\n", err,
							s.buf[s.mstart:s.mstart+o])
					}
					var l int
					if o+s.mstart < s.bused {
						l = o + s.mstart + 40
						if l > s.bused {
							l = s.bused
						}
						if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
							Plog.LogMux(s.W, true, slog.LNOTICE,
								"error before:\n%q\n", s.buf[s.mstart+o:l])
						}
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
					pktErrEvHandler(calltr.EvParseErr,
						s.srcIP, int(s.sport), s.dstIP, int(s.dport),
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
		// if whole s.bused used, reset to buf start
		if s.mstart == s.bused {
			// point back at buffer start
			s.mstart = 0
			s.bused = 0
		}
		// if we are here => need more bytes
		if s.bused == len(s.buf) {
			// used the entire buf. => make space
			if s.mstart == 0 {
				// not enough space to move message "down" => try to grow s.buf
				if !s.growBuf() {
					// ERROR! Message too big
					goto errTooBig
				} // else grow successful
			} else {
				// "compact" buffer -> move content mstart:bused down to buf[0]
				if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
					Plog.LogMux(s.W, true, slog.LDBG,
						"Process %p making space: state %s, mstart %d,"+
							" bused %d, skip %d\n",
						s, s.state, s.mstart, s.bused, s.skip)
				}
				copy(s.buf, s.buf[s.mstart:s.bused])
				s.bused -= s.mstart
				s.mstart = 0
			}
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"Process %p after space: state %s, mstart %d,"+
						" bused %d, skip %d\n",
					s, s.state, s.mstart, s.bused, s.skip)
			}
		}
	}
	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"Process %p end: state %s, mstart %d, bused %d, skip %d\n",
			s, s.state, s.mstart, s.bused, s.skip)
	}
	return true
errTooBig:
	if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
		Plog.LogMux(s.W, true, slog.LNOTICE,
			"tcp: error message too big on stream %p: %d used,"+
				" msg = %q...\n", s, s.bused, s.buf[:30])
	}
	stats.Inc(sCnts.tooBig)
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

	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"%p %s:%d -> %s:%d Reassembled %d bufs, ignore %v\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, len(bufs), s.ignore)
	}
	if s.ignore {
		stats.Inc(sCnts.tcpIgn)
		return
	}
	for i, seg := range bufs {
		if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
			Plog.LogMux(s.W, true, slog.LDBG,
				"%p Reassembled: buf[%d] %q state %d\n",
				s, i, seg.Bytes, s.state)
		}
		s.syn = s.syn || seg.Start
		s.fin = s.fin || seg.End
		if seg.Start {
			stats.Inc(sCnts.tcpSyn)
		}
		if seg.End {
			stats.Inc(sCnts.tcpFin)
		}
		if s.segs == 0 {
			// first segment ever used
			s.FinishInit() // finish allocating resources
		}
		s.segs++
		s.rcvd += uint64(len(seg.Bytes))
		stats.Inc(sCnts.tcpSegs)
		stats.Add(sCnts.tcpRcvd, counters.Val(len(seg.Bytes)))
		if s.lastRcv.After(seg.Seen) && s.segs > 1 {
			stats.Inc(sCnts.tcpOutOfOrder)
			s.oo++ // dbg
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"%p %s:%d -> %s:%d %d OO Reassembled, "+
						" after %v (%v ago), lastRcvd %v ago, created %v ago\n",
					s, s.srcIP, s.sport, s.dstIP, s.dport, s.oo,
					s.lastRcv.Sub(seg.Seen), time.Now().Sub(seg.Seen),
					time.Now().Sub(s.lastRcv), time.Now().Sub(s.created))
			}
		} else {
			s.lastRcv = seg.Seen
		}
		// TODO: if !s.sin => start not seen => ignore ?
		if seg.Skip != 0 {
			stats.Inc(sCnts.tcpMissed)
			if s.segs > 1 {
				stats.Add(sCnts.tcpMissedBytes, counters.Val(seg.Skip))
			}
			// else first pkt seen is not syn, it's a prev. estab. conn.
			//   or lessl likely re-ordering at the start
			// TODO: special stat
			if !s.SkippedBytes(seg.Skip) {
				s.ignore = true
				// TODO: free what's possible
				s.buf = nil
				if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
					Plog.LogMux(s.W, true, slog.LDBG,
						"%p %s:%d -> %s:%d skipped bytes ->DROP CONN %d\n",
						s, s.srcIP, s.sport, s.dstIP, s.dport, seg.Skip)
				}
				break // error - out of sync - ignore stream
			}
			stats.Inc(sCnts.tcpRecovered)
		}
		if !s.Process(seg.Bytes) {
			s.ignore = true
			// TODO: free what's possible
			s.buf = nil
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"%p %s:%d -> %s:%d Process failed for buf %d\n",
					s, s.srcIP, s.sport, s.dstIP, s.dport, i)
			}
			break
		}
	}
}

// implement gopacket.tcpassembly Stream
func (s *SIPStreamData) ReassemblyComplete() {
	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"stream %p %s:%d -> %s:%d closing"+
				" (%d bytes %d tcp segs. state %s"+
				" mstart %d bused %d skip %d)...\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, s.rcvd,
			s.segs, s.state, s.mstart, s.bused, s.skip)
	}
	// cleanup
	s.pmsg.Reset()
	s.state = SIPStreamFIN
	if s.ignore {
		stats.Inc(sCnts.tcpStreamIgn)
	}
	stats.Inc(sCnts.tcpClosed)
	// free data
	s.ignore = true
	s.buf = nil
}

// implement tcpassembly.Stream

type SIPStreamFactory struct {
	SIPStreamOptions
}

// implement tcpasembly.StreamFactory
func (f SIPStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	port := tcpFlow.Src().Raw()
	srcPort := uint16(port[0])<<8 + uint16(port[1])
	port = tcpFlow.Dst().Raw()
	dstPort := uint16(port[0])<<8 + uint16(port[1])

	// check if websocket or http
	if len(f.WSports) > 0 {
		for _, p := range f.WSports {
			if srcPort == p || dstPort == p {
				s := &HTTPHalfConn{}
				var cfg HTTPStreamOptions
				cfg.W = f.W // for extra DBG
				cfg.Verbose = f.Verbose
				cfg.BSize = f.bufSize
				cfg.MaxBSize = f.bufMaxSize

				s.Init(&cfg, nil)
				s.created = timestamp.Now()
				s.lastRcv = s.created
				var ip1, ip2 [16]byte
				l1 := copy(ip1[:], netFlow.Src().Raw())
				l2 := copy(ip2[:], netFlow.Dst().Raw())
				if l1 != l2 {
					Plog.BUG("New stream: different src & dst IP len: %d != %d"+
						" for %s & %d\n", l1, l2,
						net.IP(netFlow.Src().Raw()),
						net.IP(netFlow.Dst().Raw()))
				}
				s.srcIdx = InitConnKey(&s.key,
					ip1, srcPort, ip2, dstPort, uint8(l1))
				httpStats.Inc(httpCnts.tcpStreams)
				return s
			}
		}
	}
	// not websocket or http => sip

	// TODO: use a buf cache or at least sync.Pool
	// Note: there is a race check when New() is called from
	// gopacket/tcpassembly and if the race is lost there is no function
	// called to free possible resources that New() might have allocated
	// => try to allocate most of the resources on 1st seq seen and free
	// them from ReassemblyComplete()

	s := &SIPStreamData{}
	s.Init(&f.SIPStreamOptions, nil)
	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"new stream %p, options %+v\n", s, f.SIPStreamOptions)
	}
	// convert from flows to IP:port(s)
	l := copy(s.srcIP, netFlow.Src().Raw())
	s.srcIP = s.srcIP[:l]
	l = copy(s.dstIP, netFlow.Dst().Raw())
	s.dstIP = s.dstIP[:l]
	s.sport = srcPort
	s.dport = dstPort
	s.created = time.Now()
	s.lastRcv = s.created
	stats.Inc(sCnts.tcpStreams)
	return s
}
