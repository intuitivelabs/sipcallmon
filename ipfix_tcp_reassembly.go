// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree

// TCP reassembler for IPFIX connections, based on gopacket/tcpassembly.
// It is used for replaying ipfix messages from recorded pcaps
// (live ipfix support uses normal sockets).

package sipcallmon

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/slog"
	"github.com/intuitivelabs/timestamp"
)

const IPFIXmsgMaxSize = 65535 // maximum msg size we support

type ipfixStreamState uint8

const (
	ipfixStreamInit ipfixStreamState = iota
	ipfixStreamNewMsg
	ipfixStreamParsing // parsing ipfix message
	ipfixStreamMoreBytesHdr
	ipfixStreamMoreBytes
	ipfixStreamSkipBytes
	ipfixStreamSkipStop
	ipfixStreamHdrParseError
	ipfixStreamParseError
	ipfixStreamInvalidHdrLength
	ipfixStreamMsgTooBigError
	ipfixStreamSyncLost
	ipfixStreamFIN
)

var ipfixStreamState2String = [...]string{
	ipfixStreamInit:             "Init",
	ipfixStreamNewMsg:           "NewMsgReady",
	ipfixStreamParsing:          "Parsing",
	ipfixStreamMoreBytesHdr:     "MoreBytesNeededHdr",
	ipfixStreamMoreBytes:        "MoreBytesNeededConten",
	ipfixStreamSkipBytes:        "Skip",
	ipfixStreamSkipStop:         "SkipStopped",
	ipfixStreamHdrParseError:    "HdrParseError",
	ipfixStreamParseError:       "ParseError",
	ipfixStreamInvalidHdrLength: "InvHdrLenError",
	ipfixStreamMsgTooBigError:   "MsgTooBigError",
	ipfixStreamSyncLost:         "SyncLost",
	ipfixStreamFIN:              "FIN",
}

func (state ipfixStreamState) String() string {
	if int(state) < len(ipfixStreamState2String) {
		return ipfixStreamState2String[int(state)]
	}
	return "BUG"
}

type ipfixStreamOptions struct {
	bufSize    int
	bufMaxSize int
	Verbose    bool
	W          io.Writer // write debug messages here
	IPFIXcfg   AcmeIPFIXconnCfg
}

// ipfix state per stream (uni-directional connection)
type ipfixStreamData struct {
	addrBuf [32]byte
	id      uint64
	srcIP   net.IP
	dstIP   net.IP
	sport   uint16
	dport   uint16
	lastRcv time.Time
	created time.Time
	rcvd    uint64
	segs    uint64
	oo      uint64 // out of order, dbg

	c      AcmeIPFIXconn    // connection state
	mstart int              // saved current message start in buffer
	bused  int              // how much of buf is used
	skip   int              // bytes to skip (not used for now)
	state  ipfixStreamState // current state
	buf    []byte           // keep not-yet (fully) processed bytes here

	ipfixStreamOptions
	cfg Config // need a copy of the main config for RTP

	resync bool
	ignore bool
	fin    bool
	syn    bool

	ipfConnLst *AcmeIPFIXconnLst
	ipfixStats *acmeIPFIXstatsT
	stats      *ipfixTCPreassStatsT
	isInit     bool
}

func (s *ipfixStreamData) Reset(o *ipfixStreamOptions) {
	buf := s.buf
	s.c.Reset()
	var rst ipfixStreamData
	*s = rst
	s.buf = buf
	if o != nil {
		s.ipfixStreamOptions = *o
	}
	s.srcIP = s.addrBuf[:16]
	s.dstIP = s.addrBuf[16:]
}

func (s *ipfixStreamData) init(id uint64, b []byte, srcIP, dstIP net.IP,
	sport, dport uint16,
	createdTS time.Time,
	ipfixStats *acmeIPFIXstatsT, tcpStats *ipfixTCPreassStatsT,
	ipfixConnLst *AcmeIPFIXconnLst,
	o *ipfixStreamOptions, cfg *Config) {
	s.Reset(o)
	s.id = id
	s.buf = b
	l := copy(s.srcIP, srcIP) // copy content, not slice
	s.srcIP = s.srcIP[:l]
	l = copy(s.dstIP, dstIP)
	s.dstIP = s.dstIP[:l]
	s.sport = sport
	s.dport = dport
	s.created = createdTS
	s.lastRcv = s.created
	s.ipfixStats = ipfixStats
	s.stats = tcpStats
	s.ipfConnLst = ipfixConnLst
	s.isInit = true
}

func (s *ipfixStreamData) finishInit() {
	src := net.TCPAddr{
		IP:   s.srcIP,
		Port: int(s.sport),
	}
	dst := net.TCPAddr{
		IP:   s.dstIP,
		Port: int(s.dport),
	}
	s.c.Init(s.id, &src, &dst, nil, timestamp.Timestamp(s.created),
		s.ipfixStats, s.IPFIXcfg, &s.cfg)
	if s.buf == nil {
		sz := s.bufSize
		if sz == 0 {
			sz = 8192
		}
		s.buf = make([]byte, sz) // TODO sync.Pool or alloc
	}
	// keep a list of ipfix connections
	if s.ipfConnLst != nil {
		s.ipfConnLst.Lock()
		s.ipfConnLst.InsertUnsafe(&s.c)
		s.ipfConnLst.Unlock()
	}
}

// growBuf tries to grow the internal buffer, up to s.bufMaxSize.
// Returns true on success, false on error (cannot grow, max size).
func (s *ipfixStreamData) growBuf() bool {
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
		s.stats.cnts.Inc(s.stats.bufGrow)
		s.stats.cnts.Set(s.stats.bufMax, counters.Val(sz))
		return true
	}
	return false
}

func (s *ipfixStreamData) Process(data []byte) bool {
	var mHdr IPFIXmsgHdr
	var err error

	for len(data) > 0 {
		// add as much as possible from data into buf[bused]
		l := copy(s.buf[s.bused:], data)
		data = data[l:]
		s.bused += l
		var o int
		var dbgl int
		if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
			Plog.LogMux(s.W, true, slog.LDBG,
				"Process %p pre-loop: state %s, mstart %d,"+
					" bused %d, skip %d, copied %d bytes\n",
				s, s.state, s.mstart, s.bused, s.skip, l)
		}
		for err == nil && s.mstart < s.bused {
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"Process %p loop %d: state %s, mstart %d,"+
						" bused %d, skip %d\n",
					s, dbgl, s.state, s.mstart, s.bused, s.skip)
				dbgl++
			}
			// try every time to get/parse a whole ipfix packet
			// (we could keep some state like ipfixNewMsg and ipfixParseContent
			//  but this would only avoid an extra 16 bytes header parsing each
			//  time an ipfix packet is not full contained in a tcp segment =>
			//  not worse it, especially since this code is only for replaying
			//  pcaps and no live use).
			mHdr, o, _, err = ParseIPFIXmsgHdr(s.buf[s.mstart:s.bused], 0)
			if err != nil {
				if err == ErrIPFIXmoreBytes {
					// incomplete header, wait for more and retry
					s.state = ipfixStreamMoreBytesHdr
					break
				}
				// invalid header => drop connection
				// stats + dbg
				s.stats.cnts.Inc(s.stats.hdrErrs)
				s.stats.cnts.Inc(s.stats.errs)
				if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
					Plog.LogMux(s.W, true, slog.LNOTICE,
						"tcp: ipfix reassembly: unexpected error after parsing "+
							"stream sync lost for %p %s:%p->%s:%p => %s\n",
						s, s.srcIP.String(), s.sport,
						s.dstIP.String(), s.dport, err)
					fmt.Fprintln(s.W)
				}
				// actual work
				s.state = ipfixStreamHdrParseError
				s.mstart += o
				return false // error
			}
			totalLen := int(mHdr.Length)
			if totalLen < IPFIXmsgHdrLen || totalLen > IPFIXmsgMaxSize {
				// invalid length
				s.stats.cnts.Inc(s.stats.errs)
				s.stats.cnts.Inc(s.stats.hdrLenErrs)
				s.state = ipfixStreamInvalidHdrLength
				s.mstart += o
				return false // error
			}
			if (s.bused - s.mstart) < totalLen {
				// incomplete message, wait for more bytes
				s.state = ipfixStreamMoreBytes
				break
			}
			ts := timestamp.Now()
			// handlePkt will not respond to pings, because there is no tcpconn
			// set (s.c.conn is empty)
			err = s.c.handlePkt(mHdr, s.buf[s.mstart:s.mstart+totalLen], ts, &s.cfg)
			if err != nil {
				s.stats.cnts.Inc(s.stats.errs)
				s.state = ipfixStreamParseError
				s.mstart += totalLen // skip over current msg
				return true          // ignore current message
			}
			s.stats.cnts.Inc(s.stats.ok)
			// prepare for new message
			s.mstart += totalLen // next message
			s.state = ipfixStreamNewMsg
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
					if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
						Plog.LogMux(s.W, true, slog.LNOTICE,
							"tcp: error message too big on stream %p: %d used,"+
								" msg = %q...\n", s, s.bused, s.buf[:30])
					}
					s.state = ipfixStreamMsgTooBigError
					s.stats.cnts.Inc(s.stats.tooBig)
					return false // error
				} // else grow successful
			} else {
				// "compact" buffer -> move content mstart:bused down to buf[0]
				if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
					Plog.LogMux(s.W, true, slog.LDBG,
						"Process %p making space: state %s, mstart %d,"+
							" bused %d\n",
						s, s.state, s.mstart, s.bused)
				}
				copy(s.buf, s.buf[s.mstart:s.bused])
				s.bused -= s.mstart
				s.mstart = 0
			}
			if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
				Plog.LogMux(s.W, true, slog.LDBG,
					"Process %p after space: state %s, mstart %d,"+
						" bused %d\n",
					s, s.state, s.mstart, s.bused)
			}
		}
	}
	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"Process %p end: state %s, mstart %d, bused %d\n",
			s, s.state, s.mstart, s.bused)
	}
	return true
}

// called when n bytes are missing
func (s *ipfixStreamData) SkippedBytes(n int) bool {
	// allow only if inside body (SkipBytes mode)
	switch s.state {
	case ipfixStreamSkipBytes:
		if s.skip >= n {
			s.skip -= n
			if s.skip == 0 {
				s.state = ipfixStreamSkipStop
			}
			return true
		} else {
			// try re-covering
			// for now just return ok, if something is wrong
			// we'll get a parsing error later, Process will return false
			// and the stream will be marked as invalud
			s.skip = 0
			s.state = ipfixStreamSkipStop
			return true
		}
	case ipfixStreamInit:
		return true // allow skipped packets at the beginning
	case ipfixStreamNewMsg:
		return true // allow skipped packets between messages
	case ipfixStreamSkipStop:
		return true // allow skipped packets
	case ipfixStreamHdrParseError, ipfixStreamParseError, ipfixStreamInvalidHdrLength,
		ipfixStreamMsgTooBigError, ipfixStreamSyncLost, ipfixStreamFIN:
		return true // allow skipped bytes in these states
	default:
		s.state = ipfixStreamSyncLost
		s.mstart = 0 // discard everything
		s.bused = 0
	}
	// TODO: try re-sync, look up for new header like?
	s.state = ipfixStreamSyncLost
	return false
}

// implement gopacket.tcpassembly Stream
func (s *ipfixStreamData) Reassembled(bufs []tcpassembly.Reassembly) {

	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"%p %s:%d -> %s:%d Reassembled %d bufs, ignore %v\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, len(bufs), s.ignore)
	}
	if s.ignore {
		s.stats.cnts.Inc(s.stats.tcpIgn)
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
			s.stats.cnts.Inc(s.stats.tcpSyn)
		}
		if seg.End {
			s.stats.cnts.Inc(s.stats.tcpFin)
		}
		if s.segs == 0 {
			// first segment ever used
			s.finishInit() // finish allocating resources
		}
		s.segs++
		s.rcvd += uint64(len(seg.Bytes))
		s.stats.cnts.Inc(s.stats.tcpSegs)
		s.stats.cnts.Add(s.stats.tcpRcvd, counters.Val(len(seg.Bytes)))
		if s.lastRcv.After(seg.Seen) && s.segs > 1 {
			s.stats.cnts.Inc(s.stats.tcpOutOfOrder)
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
			s.stats.cnts.Inc(s.stats.tcpMissed)
			if s.segs > 1 {
				s.stats.cnts.Add(s.stats.tcpMissedBytes, counters.Val(seg.Skip))
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
			s.stats.cnts.Inc(s.stats.tcpRecovered)
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
func (s *ipfixStreamData) ReassemblyComplete() {
	if s.Verbose && (Plog.DBGon() || s.W != ioutil.Discard) {
		Plog.LogMux(s.W, true, slog.LDBG,
			"stream %p %s:%d -> %s:%d closing"+
				" (%d bytes %d tcp segs. state %s"+
				" mstart %d bused %d skip %d)...\n",
			s, s.srcIP, s.sport, s.dstIP, s.dport, s.rcvd,
			s.segs, s.state, s.mstart, s.bused, s.skip)
	}
	// cleanup
	s.state = ipfixStreamFIN
	if s.ignore {
		s.stats.cnts.Inc(s.stats.tcpStreamIgn)
	}
	s.stats.cnts.Inc(s.stats.tcpClosed)
	// free data
	s.ignore = true
	s.buf = nil
	lifetime := timestamp.Now().Sub(s.c.startTS) / time.Second
	s.ipfixStats.cnts.Set(s.ipfixStats.hMaxClifetime,
		counters.Val(lifetime))
	s.ipfixStats.cnts.Dec(s.ipfixStats.hActiveConns)
	//  remove from active AcmeIPFIXconnLst
	if s.ipfConnLst != nil {
		s.ipfConnLst.Lock()
		s.ipfConnLst.RmUnsafe(&s.c)
		s.ipfConnLst.Unlock()
	}
	s.c.Reset()
}

// implement tcpassembly.Stream

type ipfixStreamFactory struct {
	ipfixStreamOptions
	cfg          Config
	ipfixStats   *acmeIPFIXstatsT
	stats        *ipfixTCPreassStatsT
	ipfixConnLst *AcmeIPFIXconnLst
	init         bool
}

func (f *ipfixStreamFactory) Init(opts ipfixStreamOptions, cfg *Config) error {
	f.ipfixStreamOptions = opts
	f.cfg = *cfg
	// init stats
	acmeIPFIXstatsLock.Lock()
	if acmeIPFIXstats == nil {
		acmeIPFIXstats = &acmeIPFIXstatsT{}
		if !acmeIPFIXstats.Init() {
			acmeIPFIXstats = nil
			acmeIPFIXstatsLock.Unlock()
			return fmt.Errorf("ipfix tcp reassembly: failed to init ipfix" +
				" stats\n")
		}
	}
	f.ipfixStats = acmeIPFIXstats
	acmeIPFIXstatsLock.Unlock()

	ipfixTCPreassStatsLock.Lock()
	if ipfixTCPreassStats == nil {
		ipfixTCPreassStats = &ipfixTCPreassStatsT{}
		if !ipfixTCPreassStats.Init() {
			ipfixTCPreassStats = nil
			ipfixTCPreassStatsLock.Unlock()
			return fmt.Errorf("ipfix tcp reassembly: failed to init tcp" +
				" stats\n")
		}
	}
	f.stats = ipfixTCPreassStats
	ipfixTCPreassStatsLock.Unlock()

	if acmeIPFIXreassLst.IsInit() {
		f.ipfixConnLst = &acmeIPFIXreassLst
	} else {
		BUG("ipfix tcp reassembly init with uninitialized acmeIPFIXreassLst\n")
	}
	f.init = true
	return nil
}

// implement tcpassembly.StreamFactory
func (f ipfixStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	port := tcpFlow.Src().Raw()
	srcPort := uint16(port[0])<<8 + uint16(port[1])
	port = tcpFlow.Dst().Raw()
	dstPort := uint16(port[0])<<8 + uint16(port[1])

	// TODO: use a buf cache or at least sync.Pool
	// Note: there is a race check when New() is called from
	// gopacket/tcpassembly and if the race is lost there is no function
	// called to free possible resources that New() might have allocated
	// => try to allocate most of the resources on 1st seq seen
	// (finishInit() in Reassembly) and free them from ReassemblyComplete()

	s := &ipfixStreamData{}
	if f.Verbose && (Plog.DBGon() || f.W != ioutil.Discard) {
		Plog.LogMux(f.W, true, slog.LDBG,
			"new stream %p, options %+v\n", s, f.ipfixStreamOptions)
	}
	f.stats.cnts.Inc(f.stats.tcpStreams)
	f.ipfixStats.cnts.Inc(f.ipfixStats.hActiveConns)
	id := uint64(f.ipfixStats.cnts.Inc(f.ipfixStats.hTotalConns))
	s.init(id, nil, netFlow.Src().Raw(), netFlow.Dst().Raw(),
		srcPort, dstPort, time.Now(),
		f.ipfixStats, f.stats, f.ipfixConnLst,
		&f.ipfixStreamOptions, &f.cfg)
	return s
}
