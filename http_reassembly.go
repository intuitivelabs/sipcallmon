// Copyright 2022 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE_BSD.txt file in the root of the source
// tree.

// TCP reassembler for HTTP connections and websockets, based on
//    gopacket/tcpassembly
// There are 2 modes for reassembling a HTTP connection: hConnSimpleHTTP that
// does not try to associate the 2 halves of the TCP connection (usable
// only for simple HTTP statistics or basic websocket/sip with no special
// parameters that depend on the other side) and a full duplex HTTP, that
// associates the 2 uni-directional halves of the TCP connections and tries
// to replay the packets in-order across them.
//
// TODO: full-duplex mode:
// tcpassembly assembles only half-connections (or uni-directional
// tcp streams) so for the "full duplex" HTTP we need to associate
// the half-connections to a tcp connection and to replay the packets in an
// order that makes sense for HTTP (basically if the packets are out of order
// we need to block one side until we get a packet from the other
// half-connection).
// The ordering is done at the HTTP level, using the fact that HTTP 1.x
// connections are  always 1 request -> 1 reply.
//
// If switching to websocket/sip we stop trying to enforce a processing order
// for the 2 half-connection packets (we rely on the fact that SIP can match
// replies & requests independent on the processing order).

package sipcallmon

import (
	"sync"

	//	"github.com/google/gopacket"
	"fmt"
	"github.com/google/gopacket/tcpassembly"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/httpsp"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/slog"
	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/websocket"
)

// HTTPStreamOptions contains configuration options for each
// TCP HTTP or websocket connection or half connection
type HTTPStreamOptions struct {
	Verbose  bool
	W        io.Writer // for writing debugging messages
	BSize    int       // connection parse buffer size
	MaxBSize int       // maximum buffer size (grows between BSize & MaxBSize)
}

type httpHConnMode uint8

const (
	hConnInit httpHConnMode = iota
	hConnIgnore
	//hConnSkipBytes
	hConnSimpleHTTP // simple, half-http connection
	hConnWSSIP
	hConnClosed
	hConnErr
	hConnFIN
)

type httpState uint8

const (
	httpInit httpState = iota
	httpParsingMsg
	httpSkipBody
	httpSkipBytes
	httpSkipCRLF
	httpWaitProc // wait for other side before processing
	httpSkipEOF  // ignore everything
	httpErr
	httpSyncLost
)

type httpParsing struct {
	state      httpState
	switchMode httpHConnMode // after getting body, switch conn to this mode
	msg        httpsp.PMsg
}

type wsState uint8

type wsParsing struct {
	state wsState
	frame websocket.Frame // current frame
	// The decoded payload is relocated to mstart and each new frame
	// payload is appended after decEnd. The frame headers and control
	// frame are overwritten in the buf. The payload is un-xored in place
	// (we don't  need the original data, we can overwrite it)
	dataEnd int           // decoded offset (decEnd-mstart = total payload decoded)
	comp    bool          // compressed
	sipMsg  sipsp.PSIPMsg // prealloc message for parsing the sip packets
}

const (
	wsInit wsState = iota
	wsFrame
	wsSkipBytes
	wsSkipFrags
	wsErr
)

// HTTPHalfConn holds the state for each half-conncetion
type HTTPHalfConn struct {
	key    ConnKey       // connection "key"
	srcIdx uint8         // index for the src address & port in key
	mode   httpHConnMode // current "global type"/state for the half-conn

	httpP httpParsing // http parsing state & info if in http mode
	wsP   wsParsing   //  websocket parsing state & info if in ws mode

	lastRcv timestamp.TS
	created timestamp.TS

	mstart int    // message start offset in buf[}
	offs   int    // current offset / parsing point in buf[mstart:bused]
	bused  int    // how much of buf is used
	skip   int    // skip n bytes (e.g. skip body), -1 means skip to EOF
	buf    []byte // buffer containing data currently being parsed

	segs     uint64 // number of tcp segs received so far
	oo       uint64 // number of out of order received segs
	httpMsgs uint64 // number of http messages received and successfully parsed
	rcvd     uint64 // received total bytes
	fin      bool
	syn      bool
	ignore   bool // TODO: can be replaced by special state/mode

	other *HTTPHalfConn // pointer to the other half connection
	lock  sync.Mutex    // processing lock ("other" can trigger asyc procesing)
	// TODO: buffer queue
	cfg HTTPStreamOptions
}

// Reset re-initialises a HTTPHalfConn.
func (c *HTTPHalfConn) Reset(cfg *HTTPStreamOptions) {
	buf := c.buf // keep current buffer
	*c = HTTPHalfConn{}
	c.buf = buf
	if cfg != nil {
		c.cfg = *cfg
	}
	c.httpP.msg.Reset()
	c.wsP.frame.Reset()
}

// Init initialises a HTTPHalfConn.
// The parameters are the per-connection options and a buffer that will be
// used to re-construct messages (so that messages can be parsed).
func (c *HTTPHalfConn) Init(cfg *HTTPStreamOptions, b []byte) {
	c.Reset(cfg)
	c.httpP.msg.Init(nil, nil) // empty buffer and no extra headers
	c.buf = b
}

// FinishInit is called on 1st packet, before processing. It's the right place
// to allocate extra resources.
func (c *HTTPHalfConn) FinishInit() {
	sz := c.cfg.BSize
	if sz == 0 {
		sz = 8192
	}
	c.buf = make([]byte, sz) // TODO: sync.Pool or alloc
}

// Destroy  is called before removing the connection. It's the right place
// to free resources.
func (c *HTTPHalfConn) Destroy() {
	c.buf = nil
}

func (c *HTTPHalfConn) SrcIP() net.IP {
	return c.key.IP0(int(c.srcIdx))
}

func (c *HTTPHalfConn) DstIP() net.IP {
	return c.key.IP1(int(c.srcIdx))
}

func (c *HTTPHalfConn) SrcPort() uint16 {
	return c.key.Port0(int(c.srcIdx))
}

func (c *HTTPHalfConn) DstPort() uint16 {
	return c.key.Port1(int(c.srcIdx))
}

// growBuf tried to grow the internal buffer, up to c.cfg.MaxBSize.
// returns true on success, false on error (cannot grow, max size)
func (c *HTTPHalfConn) growBuf() bool {
	if len(c.buf) < c.cfg.MaxBSize {
		sz := 2 * len(c.buf)
		if sz > c.cfg.MaxBSize {
			sz = c.cfg.MaxBSize
		}
		b := make([]byte, sz) // TODO: sync.Pool or alloc
		// copy only the used part
		copy(b, c.buf[c.mstart:c.bused])
		c.buf = b // TODO: put/free c.buf
		c.bused -= c.mstart
		c.wsP.dataEnd -= c.mstart
		c.mstart = 0
		httpStats.Inc(httpCnts.bufGrow)
		httpStats.Set(httpCnts.bufMax, counters.Val(sz))
		return true
	}
	return false
}

// advMStart skips over l bytes, advancing the message start
// (initialises parsing for a new message, starting at mstart +l)
func (c *HTTPHalfConn) advMStart(l int) {
	c.mstart += l
	c.offs = 0
}

// prepareNewHTTPmsg prepares parsing a new HTTP message starting
// l bytes after current mstart in state s.
func (c *HTTPHalfConn) prepareNewHTTPmsg(l int, s httpState) {
	c.advMStart(l)
	c.httpP.msg.Reset()
	c.httpP.state = s
}

func (c *HTTPHalfConn) httpModeSwitch() bool {
	return c.httpP.switchMode != hConnSimpleHTTP
}

// handleHTTPmsg  handles a newly parsed HTTP msg (w/o body).
// It returns the body type (or MsgNoBody if body already parsed or handled
// some other way) and the next parent connection state (either HTTP or
// if an upgrade, something else).
func (c *HTTPHalfConn) handleHTTPmsg() (httpsp.MsgPState, httpHConnMode) {
	btype := httpsp.MsgNoBody
	connType := hConnSimpleHTTP
	if !c.httpP.msg.Parsed() {
		if !c.httpP.msg.ParsedHdrs() {
			return httpsp.MsgErr, connType
		}
		// body not (fully) parsed
		btype = c.httpP.msg.BodyType(httpsp.MUndef)
	}
	if !c.httpP.msg.Request() &&
		(c.httpP.msg.FL.Status > 299 || c.httpP.msg.FL.Status < 100) {
		if c.httpP.msg.PV.Upgrade.Parsed() {
			httpStats.Inc(httpCnts.upgradeReplErr)
		}
		// negative or unknown reply, ignore upgrade or other header fields
		return btype, connType
	}
	// Look for upgrade
	if c.httpP.msg.PV.Upgrade.Parsed() {
		connType = hConnIgnore // upgrade to unknown protocol or WS sub-proto
		if c.httpP.msg.Request() {
			httpStats.Inc(httpCnts.upgradeReq)
		} else {
			httpStats.Inc(httpCnts.upgradeReplOk)
		}
		if c.httpP.msg.PV.Upgrade.Protos&httpsp.UProtoWSockF != 0 {
			httpStats.Inc(httpCnts.upgWS)
			// websocket upgrade
			if c.httpP.msg.PV.WSProto.Parsed() &&
				(c.httpP.msg.PV.WSProto.Protos&httpsp.WSProtoSIPF != 0) {
				httpStats.Inc(httpCnts.upgWSSIP)
				connType = hConnWSSIP
			}
		}
	}
	return btype, connType
}

// httpHProcess handles http in half-connection mode.
// In this mode no attempt is made to synchronize between the 2 sides of
// a connection and each half is processed completely independent from the
// other. Is faster and lower memory than full-mode but can be used only
// in simple cases, like dedicated websocket only connections with no
// special compression parameters or statistics.
// Adapted from sip tcp_reassembly.go SIPStreamData.Process().
func (c *HTTPHalfConn) httpHProcess(data []byte) bool {
	// TODO: zero copy mode if no buffered data and there is enough
	//       data in the passed buffer to parse the whole message
	for len(data) > 0 {
		// add as much as possible from data into buf[bused]
		l := copy(c.buf[c.bused:], data)
		data = data[l:]
		c.bused += l
		var err httpsp.ErrorHdr
		var o int
		var dbgl int
		if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
			Plog.LogMux(c.cfg.W, true, slog.LDBG,
				"Process http %p pre-loop: state %d, mstart %d,"+
					" bused %d, skip %d, copied %d bytes\n",
				c, c.httpP.state, c.mstart, c.bused, c.skip, l)
		}
		for err == 0 && c.mstart < c.bused {
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"Process http %p loop %d: state %d, mstart %d,"+
						" bused %d, skip %d\n",
					c, dbgl, c.httpP.state, c.mstart, c.bused, c.skip)
				dbgl++
			}
			switch c.httpP.state {
			case httpParsingMsg:
				o, err = httpsp.ParseMsg(c.buf[c.mstart:c.bused], c.offs,
					&c.httpP.msg, httpsp.MsgSkipBodyF)
				c.offs = o
				if c.cfg.Verbose && (Plog.DBGon() ||
					c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"tcp after parsing http msg => %d, %s\n",
						o, err)
				}
				switch err {
				case 0:
					httpStats.Inc(httpCnts.ok)
					if c.httpP.msg.Request() {
						httpStats.Inc(httpCnts.reqsN)
						httpStats.Inc(httpCnts.method[c.httpP.msg.FL.MethodNo])
					} else {
						httpStats.Inc(httpCnts.replsN)
						if c.httpP.msg.FL.Status < 1000 {
							httpStats.Inc(
								httpCnts.repl[c.httpP.msg.FL.Status/100])
						}
					}
					if c.cfg.Verbose {
						fmt.Fprintln(c.cfg.W)
					}

					btype, swConnMode := c.handleHTTPmsg()
					c.httpP.switchMode = swConnMode
					switch btype {
					// handle the no body case here
					case httpsp.MsgBodyCLen:
						// check if != 0
						if c.httpP.msg.PV.CLen.UIVal > 0 {
							c.httpP.state = httpSkipBytes
							c.skip = int(c.httpP.msg.PV.CLen.UIVal)
							break
						}
						// else 0 CLen => no body
						fallthrough
					case httpsp.MsgNoBody:
						// no body => reset & wait for new message
						// prepare for new message
						c.prepareNewHTTPmsg(o, httpSkipCRLF)
						if c.httpModeSwitch() {
							return c.processData(c.httpP.switchMode, data)
						}
					case httpsp.MsgBodyEOF:
						// body till EOF => ignore
						// TODO: ignore at "upper" level
						c.prepareNewHTTPmsg(o, httpSkipEOF)
						if c.httpModeSwitch() {
							return c.processData(c.httpP.switchMode, data)
						}
					case httpsp.MsgBodyChunked:
						c.httpP.state = httpSkipBody
					case httpsp.MsgErr:
						c.prepareNewHTTPmsg(o, httpErr)
						// alternative: ignore to EOF?
						goto errParse
					default:
						Plog.BUG("unexpected error for http body type "+
							" parsed ok:\n%q\n",
							c.buf[c.mstart:c.mstart+o])
						c.prepareNewHTTPmsg(o, httpErr)
						goto errParse
					}
				case httpsp.ErrHdrMoreBytes:
					// do nothing (end loop -> not enough bytes for whole msg)
					//... stats ?
				default:
					httpStats.Inc(httpCnts.errs)
					httpStats.Inc(httpCnts.errType[err])
					if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
						Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
							"http: tcp: unexpected error after parsing "+
								"stream sync lost for %p => %s\n", c, err)
						Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
							"http: parsed ok:\n%q\n",
							c.buf[c.mstart:c.mstart+o])
						fmt.Fprintln(c.cfg.W)
					} else if err == httpsp.ErrHdrBug ||
						err == httpsp.ErrConvBug {
						// show parsing bug always
						Plog.BUG("http: unexpected error after parsing => %s ,"+
							" parsed ok:\n%q\n", err,
							c.buf[c.mstart:c.mstart+o])
					}
					var l int
					if o+c.mstart < c.bused {
						l = o + c.mstart + 40
						if l > c.bused {
							l = c.bused
						}
						if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
							Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
								"http: error before:\n%q\n", c.buf[c.mstart+o:l])
						}
					}
					/* TODO: event for http parse error ?
					// parse error event
					rep := o
					if rep+c.mstart > c.bused {
						rep = c.bused - c.mstart
					}
					// report first 60 parsed ok chars from the message
					if rep > 60 {
						rep = 60
					}
					pktErrEvHandler(calltr.EvParseErr,
						c.SrcIP(), int(c.SrcPort()),
						c.DstIP(), int(c.DstPort()),
						calltr.NProtoTCP,
						nil,
						c.buf[c.mstart:c.mstart+rep])
					*/
					// actual work
					c.prepareNewHTTPmsg(o, httpErr)
					goto errParse
				}
			case httpInit:
				c.httpP.state = httpSkipCRLF
				fallthrough
			case httpSkipCRLF:
			skipcrlf:
				//advance mstart till first non CRLF char found
				for ; c.mstart < c.bused; c.mstart++ {
					switch c.buf[c.mstart] {
					case '\r', '\n': // do nothing, skip over them
					default:
						c.offs = 0
						c.httpP.state = httpParsingMsg
						break skipcrlf
					}
				}
			case httpSkipBody:
				o, err = httpsp.SkipBody(c.buf[c.mstart:c.bused], c.offs,
					&c.httpP.msg, 0)
				c.offs = o
				if c.cfg.Verbose && (Plog.DBGon() ||
					c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"http: tcp after skip http body => %d, %s\n",
						o, err)
				}
				switch err {
				case 0:
					httpStats.Inc(httpCnts.bodyOk)
					// prepare for new message
					c.prepareNewHTTPmsg(o, httpSkipCRLF)
					if c.httpModeSwitch() {
						return c.processData(c.httpP.switchMode, data)
					}
				case httpsp.ErrHdrMoreBytes:
					// do nothing (end loop -> not enough bytes for whole body)
				default:
					httpStats.Inc(httpCnts.errs)
					httpStats.Inc(httpCnts.bodyErrs)
					httpStats.Inc(httpCnts.errType[err])
					if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
						Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
							"http: tcp: unexpected error after parsing "+
								"stream sync lost for %p => %s\n", c, err)
						Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
							"http parsed ok:\n%q\n",
							c.buf[c.mstart:c.mstart+o])
						fmt.Fprintln(c.cfg.W)
					} else if err == httpsp.ErrHdrBug ||
						err == httpsp.ErrConvBug {
						// show parsing bug always
						Plog.BUG("http unexpected error after parsing => %s ,"+
							" parsed ok:\n%q\n", err,
							c.buf[c.mstart:c.mstart+o])
					}
					var l int
					if o+c.mstart < c.bused {
						l = o + c.mstart + 40
						if l > c.bused {
							l = c.bused
						}
						if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
							Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
								"http error before:\n%q\n", c.buf[c.mstart+o:l])
						}
					}
					// TODO: event for http parse error ?

					c.prepareNewHTTPmsg(o, httpErr)
					// try to recover?
					goto errParse
				}
			case httpSkipBytes:
				// TODO: should be moved at upper level (common for http & ws)
				// TODO: if c.skip == -1 => httpSkipEOF
				if (c.mstart + c.skip) <= c.bused {
					c.mstart += c.skip
					c.skip = 0
					c.prepareNewHTTPmsg(0, httpSkipCRLF)
					c.httpP.state = httpSkipCRLF
				} else {
					c.skip -= (c.bused - c.mstart)
					c.mstart = c.bused
				}
			case httpSkipEOF, httpSyncLost, httpErr:
				// ignore everything
				c.mstart = c.bused
				c.offs = 0
				// TODO: ? c.skip = -1
			default:
				Plog.BUG("unhandled http state %d for %p mode %d\n",
					c.httpP.state, c, c.mode)
				// TODO: ? c.skip = -1
			}
		}
		// if we are here => need more bytes
		if c.bused == len(c.buf) {
			// used the entire buf. => make space
			if c.mstart == 0 {
				// not enough space to move message "down"
				// grow c.buf, have cfg.maxBuf
				if !c.growBuf() {
					// failure
					goto errTooBig
				}
				// grow successful
			} else {
				if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"Process http %p making space: state %d, mstart %d,"+
							" bused %d, skip %d\n",
						c, c.httpP.state, c.mstart, c.bused, c.skip)
				}
				copy(c.buf, c.buf[c.mstart:c.bused])
				c.bused -= c.mstart
				c.mstart = 0
			}
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"Process http %p after space: state %d, mstart %d,"+
						" bused %d, skip %d len %d\n",
					c, c.httpP.state, c.mstart, c.bused, c.skip, len(c.buf))
			}
		}
	}
	if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
		Plog.LogMux(c.cfg.W, true, slog.LDBG,
			"Process http %p end: hstate %d, mstart %d, bused %d, skip %d\n",
			c, c.httpP.state, c.mstart, c.bused, c.skip)
	}
	return true
errTooBig:
	if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
		Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
			"http tcp: error message too big on stream %p: %d used,"+
				" msg = %q...\n", c, c.bused, c.buf[:30])
	}
	httpStats.Inc(httpCnts.tooBig)
errParse:
	return false // error
}

// httpHskippedBytes is called when n bytes are missing on a simple/half
// http connection.
// It returns true if it's ok, false if cannot recover.
func (c *HTTPHalfConn) httpHSkippedBytes(n int) bool {
	switch c.httpP.state {
	case httpInit, httpErr, httpSkipEOF, httpSyncLost:
		return true
	case httpSkipCRLF:
		// try allowing it
		return true
	case httpSkipBytes:
		if c.skip >= n {
			c.skip -= n
			if c.skip == 0 {
				c.prepareNewHTTPmsg(0, httpSkipCRLF)
			}
			return true
		} else {
			// try recover (rely on later parse error)
			c.skip = 0
			c.prepareNewHTTPmsg(0, httpSkipCRLF)
			return true
		}
	case httpParsingMsg, httpSkipBody:
		c.mstart = 0
		c.bused = 0
		c.offs = 0
		c.httpP.msg.Reset()
		c.httpP.state = httpSyncLost
	}
	return false
}

// wsSkippedBytes is called when n bytes are missing on websocket
// upgraded http half-connection.
// It returns true if it's ok, false if cannot recover.
func (c *HTTPHalfConn) wsSkippedBytes(n int) bool {
	switch c.wsP.state {
	case wsInit:
		return true
	case wsFrame:
		// try to recover: skip current frame
		// if header parsed and n inside the frame
		// parsing a frame
		if !c.wsP.frame.Header.DecodedF ||
			uint64(n) > c.wsP.frame.Len() {
			return false
		}
		c.skip = int(c.wsP.frame.Len())
		// TODO: repl. w/ c.prepareNewWSmsg(c.offs, c.wsP.state)
		c.offs = 0
		c.wsP.dataEnd = c.mstart
		c.wsP.frame.Reset()
		c.wsP.comp = false
		c.wsP.state = wsSkipBytes
		fallthrough
	case wsSkipBytes:
		if c.skip >= n {
			c.skip -= n
			if c.skip == 0 {
				c.wsP.state = wsSkipFrags
			}
			return true
		}
		return false // could not recover
	}
	return false
}

// skippedBytes is called when n bytes are missing.
// returns true if it's ok, false if cannot recover.
func (c *HTTPHalfConn) skippedBytes(n int) bool {
	switch c.mode {
	case hConnInit:
		return true // allow skipped packets at the beginning
	case hConnIgnore, hConnClosed, hConnErr:
		return true
	case hConnSimpleHTTP:
		return c.httpHSkippedBytes(n)
	case hConnWSSIP:
		return c.wsSkippedBytes(n)
	// TODO: hConnSkipBytes
	default:
		Plog.BUG("unexpected connection mode %d for %p\n", c.mode, c)
	}
	return false
}

// wsReset resets the state kept by websocket
func (c *HTTPHalfConn) wsReset() {
	c.wsP.state = wsInit
	c.wsP.frame.Reset()
	c.wsP.dataEnd = c.mstart
}

func (c *HTTPHalfConn) wsSIPMsg(b []byte) sipsp.ErrorHdr {
	var i int
skip_crlf:
	for i = 0; i < len(b); i++ {
		switch b[i] {
		case '\n', '\r':
			// do nothing
		default:
			break skip_crlf
		}
	}
	b = b[i:]
	if len(b) < 12 {
		if len(b) == 0 {
			// empty buffer (CRLF ping)
			wsStats.Inc(wsCnts.sipEmpty)
			return sipsp.ErrHdrOk
		} else {
			// message too small
			wsStats.Inc(wsCnts.sipTooSmall)
			return sipsp.ErrHdrTrunc
		}
	}
	c.wsP.sipMsg.Init(nil, nil, nil)
	smsg := &c.wsP.sipMsg
	o, err := sipsp.ParseSIPMsg(b, 0, smsg,
		sipsp.SIPMsgSkipBodyF|sipsp.SIPMsgNoMoreDataF)
	switch err {
	case 0:
		stats.Inc(sCnts.ok)
		stats.Inc(sCnts.sipWS)
		if smsg.FL.Request() {
			stats.Inc(sCnts.reqsN)
			stats.Inc(sCnts.method[smsg.FL.MethodNo])
		} else {
			stats.Inc(sCnts.replsN)
			if smsg.FL.Status < 1000 {
				stats.Inc(sCnts.repl[smsg.FL.Status/100])
			}
		}
		if c.cfg.Verbose {
			fmt.Fprintln(c.cfg.W)
		}

		var endPoints [2]calltr.NetInfo
		endPoints[0].SetIP(c.SrcIP())
		endPoints[0].Port = c.SrcPort()
		endPoints[0].SetProto(calltr.NProtoWS)
		endPoints[1].SetIP(c.DstIP())
		endPoints[1].Port = c.DstPort()
		endPoints[1].SetProto(calltr.NProtoWS)
		ok := CallTrack(smsg, endPoints)
		if ok {
			stats.Inc(sCnts.callTrWS)
		} else {
			if c.cfg.Verbose &&
				(Plog.L(slog.LERR) || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LERR,
					"ERROR: ws CallTrack failed\n")
			}
			stats.Inc(sCnts.callTrErrWS)
		}

	default:
		// error, no ErrHdrMoreBytes accepted on WS
		// stats + dbg
		stats.Inc(sCnts.errs)
		stats.Inc(sCnts.errsWS)
		stats.Inc(sCnts.errType[err])
		stats.Inc(wsCnts.sipErrType[err])
		if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
			Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
				"ws: unexpected error after parsing "+
					"stream sync lost for %p => %s\n", c, err)
			Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
				"parsed ok:\n%q\n", b[:o])
			fmt.Fprintln(c.cfg.W)
		} else if err == sipsp.ErrHdrBug ||
			err == sipsp.ErrConvBug {
			// show parsing bug always
			Plog.BUG("unexpected error after parsing => %s ,"+
				" parsed ok:\n%q\n", err, b[:o])
		}
		var l int
		if o < len(b) {
			l = o + 40
			if l > len(b) {
				l = len(b)
			}
			if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
				Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
					"error before:\n%q\n", b[o:l])
			}
		}
		// parse error event
		rep := o
		if rep > len(b) {
			rep = len(b)
		}
		// report first 60 parsed ok chars from the message
		if rep > 60 {
			rep = 60
		}
		pktErrEvHandler(calltr.EvParseErr,
			c.SrcIP(), int(c.SrcPort()),
			c.DstIP(), int(c.DstPort()),
			calltr.NProtoWS,
			smsg.PV.GetCallID().CallID.Get(b),
			b[:rep])
	}
	return err
}

// wsProcess handles websocket data.
// It tries to go frame by frame and xor-decode or defragment in-place
// (overwriting original data).
// TODO: handle decompression...
func (c *HTTPHalfConn) wsProcess(data []byte) bool {
	for len(data) > 0 {
		// add as much as possible from data into buf[bused]
		l := copy(c.buf[c.bused:], data)
		data = data[l:]
		c.bused += l
		var o int
		var dbgl int
		if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
			Plog.LogMux(c.cfg.W, true, slog.LDBG,
				"Process ws %p  pre-loop: state %d, mstart %d,"+
					" bused %d, skip %d, copied %d from %d bytes\n",
				c, c.wsP.state, c.mstart, c.bused, c.skip, l, l+len(data))
		}
		err := websocket.ErrMsgOk
		for err == websocket.ErrMsgOk && c.mstart < c.bused {
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"Process ws %p  loop %d: state %d, mstart %d,"+
						" bused %d, skip %d\n",
					c, dbgl, c.wsP.state, c.mstart, c.bused, c.skip)
				dbgl++
			}
			switch c.wsP.state {
			case wsInit:
				c.wsP.state = wsFrame
				fallthrough
			case wsFrame, wsSkipFrags:
				o, err = c.wsP.frame.Decode(c.buf[c.mstart:c.bused], c.offs)
				// hack to avoid Decode() out of buf bug when hdr parsed
				if o > (c.bused - c.mstart) {
					err = websocket.ErrDataMoreBytes
					o = c.offs
				}
				c.offs = o
				if c.cfg.Verbose && (Plog.DBGon() ||
					c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"after parsing ws msg => %d, %s frame len %d\n",
						o, err, c.wsP.frame.Len())
				}
				switch err {
				case websocket.ErrMsgOk:
					if c.wsP.frame.Ctrl() {
						wsStats.Inc(wsCnts.ctrlFrames)
						c.wsP.frame.Reset() // prepare for next frame
						break
					}
					if c.wsP.state == wsSkipFrags {
						if c.wsP.frame.First() {
							// keep it
							c.wsP.state = wsFrame
						} else {
							// prepare for new frames
							// TODO: repl. w/ c.prepareNewWSmsg(c.offs, c.wsP.state)
							c.mstart += c.offs
							c.offs = 0
							c.wsP.dataEnd = c.mstart
							c.wsP.frame.Reset()
							c.wsP.comp = false
							break // skip over this frame
						}
					}
					wsStats.Inc(wsCnts.sipFrames)
					if !c.wsP.frame.OnlyOne() {
						wsStats.Inc(wsCnts.sipFrags)
					}
					if c.wsP.frame.Compressed() {
						wsStats.Inc(wsCnts.sipCompFrames)
						c.wsP.comp = true
					}
					// un-mask the data in-place
					c.wsP.frame.Mask(c.buf[c.mstart:c.bused])
					dstart := c.mstart
					if !c.wsP.frame.OnlyOne() {
						// compact it -> append to previous decoded frag data
						copy(c.buf[c.wsP.dataEnd:],
							c.wsP.frame.PayloadData(c.buf[c.mstart:c.bused]))
						c.wsP.dataEnd += int(c.wsP.frame.Pf().Len)
					} else {
						// no fragments, set dstart & dataEnd to data payload
						// (avoid copying)
						dstart += int(c.wsP.frame.Pf().Offs)
						c.wsP.dataEnd = c.mstart + int(c.wsP.frame.Len())
					}
					dend := c.wsP.dataEnd
					if c.wsP.frame.Last() {
						if c.wsP.comp {
							Plog.BUG("websocket: decompression not supported\n")
							goto errDecomp
						}
						// TODO: uncompress support
						c.wsSIPMsg(c.buf[dstart:dend])
						// ignore sip msg parse errors (try to continue)

						// prepare for new frames
						// TODO: repl. w/ c.prepareNewWSmsg(c.offs, c.wsP.state)
						c.mstart += c.offs
						c.offs = 0
						c.wsP.dataEnd = c.mstart
						c.wsP.frame.Reset()
						c.wsP.comp = false
					} else {
						// prepare for more fragments
						c.wsP.frame.Reset()
					}
				case websocket.ErrHdrMoreBytes:
					// do nothing, wait for more data
				case websocket.ErrDataMoreBytes:
					if c.wsP.state == wsSkipFrags &&
						c.wsP.frame.Len() > 0 {
						// skip
						// try more frames ?
						// prepare for new frames
						// TODO: repl. w/ c.prepareNewWSmsg(c.offs, c.wsP.state)
						c.skip = int(c.wsP.frame.Len())
						c.wsP.frame.Reset()
						c.wsP.state = wsSkipBytes
						break
					}
					// else do nothing, wait for more bytes
				default:
					wsStats.Inc(wsCnts.errs)
					// try more frames ?
					// prepare for new frames
					// TODO: repl. w/ c.prepareNewWSmsg(c.offs, c.wsP.state)
					c.mstart += c.offs
					c.offs = 0
					c.wsP.dataEnd = c.mstart
					c.wsP.frame.Reset()
					c.wsP.comp = false
				}
			case wsSkipBytes:
				if (c.mstart + c.skip) <= c.bused {
					c.mstart += c.skip
					c.wsP.dataEnd = c.mstart
					c.wsP.frame.Reset()
					c.offs = 0
					c.skip = 0
					c.wsP.state = wsSkipFrags
				} else {
					c.skip -= (c.bused - c.mstart)
					c.mstart = c.bused
					c.wsP.dataEnd = c.mstart
				}
			default:
				Plog.BUG("websocket: unhandled state %d\n", c.wsP.state)
			}
		}
		// TODO: if whole c.bused used, reset to buf start:
		// if c.mstart == c.bused {c.mstart = 0; c.bused = 0}
		// if we are here => need more bytes
		if c.bused == len(c.buf) {
			// used the entire buf. => make space
			if c.mstart == 0 {
				// not enough space to move message "down"
				if c.cfg.Verbose && (Plog.DBGon() ||
					c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"Process ws %p growing buffer: state %d, mstart %d,"+
							" dEnd %d, bused %d, skip %d len(buf) %d\n",
						c, c.wsP.state, c.mstart, c.wsP.dataEnd, c.bused,
						c.skip, len(c.buf))
				}
				// grow c.buf, have cfg.maxBuf
				if !c.growBuf() {
					// failure
					goto errTooBig
				}
				// grow successful
			} else {
				if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"Process ws %p making space: state %d, mstart %d,"+
							" dEnd %d, bused %d, skip %d\n",
						c, c.wsP.state, c.mstart, c.wsP.dataEnd,
						c.bused, c.skip)
				}
				copy(c.buf, c.buf[c.mstart:c.bused])
				c.bused -= c.mstart
				c.wsP.dataEnd -= c.mstart
				c.mstart = 0
			}
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"Process ws %p after space: state %d, mstart %d,"+
						" dEnd %d, bused %d, skip %d len %d\n",
					c, c.wsP.state, c.mstart, c.wsP.dataEnd, c.bused, c.skip,
					len(c.buf))
			}
		}
	}
	if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
		Plog.LogMux(c.cfg.W, true, slog.LDBG,
			"Process ws %p end: wstate %d, mstart %d, bused %d, skip %d\n",
			c, c.wsP.state, c.mstart, c.bused, c.skip)
	}
	return true
errTooBig:
	if Plog.L(slog.LNOTICE) || c.cfg.W != ioutil.Discard {
		Plog.LogMux(c.cfg.W, true, slog.LNOTICE,
			"ws tcp: error message too big on stream %p: %d used\n", c, c.bused)
	}
	wsStats.Inc(wsCnts.tooBig)
	// errParse:
errDecomp:
	return false // error
}

func (c *HTTPHalfConn) processData(mode httpHConnMode, data []byte) bool {
	old := c.mode
	c.mode = mode
	switch mode {
	case hConnInit, hConnSimpleHTTP:
		return c.httpHProcess(data)
	case hConnIgnore, hConnClosed, hConnErr:
		return true // ignore
	case hConnWSSIP:
		if old != mode {
			c.wsReset()
		}
		return c.wsProcess(data)
	// TODO: hConnSkipBytes
	default:
		Plog.BUG("unexpected connection mode %d for %p\n", c.mode, c)
	}
	return false
}

// Reassembled implements gopacket.tcpassembly Stream interface.
func (c *HTTPHalfConn) Reassembled(bufs []tcpassembly.Reassembly) {

	if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
		Plog.LogMux(c.cfg.W, true, slog.LDBG,
			"%p %s:%d -> %s:%d Reassembled %d bufs, ignore %v\n",
			c, c.SrcIP(), c.SrcPort(), c.DstIP(), c.DstPort(),
			len(bufs), c.ignore)
	}
	if c.ignore {
		httpStats.Inc(httpCnts.tcpIgn)
		return
	}
	for i, seg := range bufs {
		if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
			Plog.LogMux(c.cfg.W, true, slog.LDBG,
				"%p Reassembled: buf[%d] %q mode %d\n",
				c, i, seg.Bytes, c.mode)
		}
		c.syn = c.syn || seg.Start
		c.fin = c.fin || seg.End
		if seg.Start {
			httpStats.Inc(httpCnts.tcpSyn)
		}
		if seg.End {
			httpStats.Inc(httpCnts.tcpFin)
		}
		if c.segs == 0 {
			// first segment ever used
			c.FinishInit() // finish allocating resources
		}
		c.segs++
		c.rcvd += uint64(len(seg.Bytes))
		httpStats.Inc(httpCnts.tcpSegs)
		httpStats.Add(httpCnts.tcpRcvd, counters.Val(len(seg.Bytes)))
		if c.lastRcv.AfterTime(seg.Seen) && c.segs > 1 {
			httpStats.Inc(httpCnts.tcpOutOfOrder)
			c.oo++ // dbg
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"%p %s:%d -> %s:%d %d OO Reassembled, "+
						" after %v (%v ago), lastRcvd %v ago, created %v ago\n",
					c, c.SrcIP(), c.SrcPort(), c.DstIP(), c.DstPort(), c.oo,
					c.lastRcv.SubTime(seg.Seen), time.Now().Sub(seg.Seen),
					timestamp.Now().Sub(c.lastRcv),
					timestamp.Now().Sub(c.created))
			}
		} else {
			c.lastRcv = timestamp.Timestamp(seg.Seen)
		}
		// TODO: if !c.sin => start not seen => ignore ?
		if seg.Skip != 0 {
			httpStats.Inc(httpCnts.tcpMissed)
			if c.segs > 1 {
				httpStats.Add(httpCnts.tcpMissedBytes, counters.Val(seg.Skip))
			}
			// else first pkt seen is not syn, it's a prev. estab. conn.
			//   or less likely re-ordering at the start
			// TODO: special stat
			if !c.skippedBytes(seg.Skip) {
				c.ignore = true
				// TODO: free what's possible
				c.buf = nil
				if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
					Plog.LogMux(c.cfg.W, true, slog.LDBG,
						"%p %s:%d -> %s:%d skipped bytes ->DROP CONN %d\n",
						c, c.SrcIP(), c.SrcPort(), c.DstIP(), c.DstPort(),
						seg.Skip)
				}
				break // error - out of sync - ignore stream
			}
			httpStats.Inc(httpCnts.tcpRecovered)
		}
		if !c.processData(c.mode, seg.Bytes) {
			c.ignore = true
			// TODO: free what's possible
			c.buf = nil
			if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
				Plog.LogMux(c.cfg.W, true, slog.LDBG,
					"%p %s:%d -> %s:%d Process failed for buf %d\n",
					c, c.SrcIP(), c.SrcPort(), c.DstIP(), c.DstPort(), i)
			}
			break
		}
	}
}

// ReassemblyComplete implements gopacket.tcpassembly Stream.
// It's called before the stream is removed (the right place to free
// resources).
func (c *HTTPHalfConn) ReassemblyComplete() {
	if c.cfg.Verbose && (Plog.DBGon() || c.cfg.W != ioutil.Discard) {
		Plog.LogMux(c.cfg.W, true, slog.LDBG,
			"stream %p %s:%d -> %s:%d closing"+
				" (%d bytes %d tcp segs. mode %d hstate %d"+
				" mstart %d bused %d skip %d)...\n",
			c, c.SrcIP(), c.SrcPort(), c.DstIP(), c.DstPort(),
			c.rcvd, c.segs, c.mode, c.httpP.state, c.mstart, c.bused, c.skip)
	}
	c.mode = hConnFIN
	if c.ignore {
		httpStats.Inc(httpCnts.tcpStreamIgn)
	}
	httpStats.Inc(httpCnts.tcpClosed)
	c.ignore = true
	// cleanup / free data
	c.Destroy()
}
