package sipcallmon

import (
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

type AcmeIPFIXconn struct {
	id        uint64
	conn      net.TCPConn
	keepAlive uint16 // keep alive in s
	lastIO    time.Time
	pktNo     uint64
	sipmsg    sipsp.PSIPMsg  // avoids allocs
	sipHdrs   [100]sipsp.Hdr // extra space for sip headers (needed for msg sig)

	gStats *acmeIPFIXstatsT // global stats (must be init)

	hnameLen uint8     // remote hostname len
	hname    [255]byte // hostname buffer

	next, prev *AcmeIPFIXconn
}

func (c *AcmeIPFIXconn) run() {

	var buf [65536]byte
	var rpos int
	var n, missing, end int
	var err error
	var mHdr IPFIXmsgHdr

	// init the sipmsg with more headers then the default of 10
	// (more headers remembered by default helps in getting a
	//   a message sig)
	c.sipmsg.Init(nil, c.sipHdrs[:], nil)

	for {
		n, err = c.conn.Read(buf[rpos:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				// connection was closed by us => clean exit
				// NOTE: net.ErrClosed available since go 1.16
				DBG("connection closed by us or EOF: %s\n", err)
				break
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				// TODO: handle deadline - set new one or exit
				ERR("acme ipfix: connection deadline\n")
				return // exit
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				WARN("acme ipfix: temporary read error on %s %s: %s\n",
					c.conn.RemoteAddr(), c.conn.LocalAddr(), ne)
				continue
			}
			ERR("acme ipfix: unrecoverable error  on %s %s: %s\n",
				c.conn.RemoteAddr(), c.conn.LocalAddr(), err)
			return // exit
		}
		if n == 0 {
			// EOF
			DBG("connection EOF\n")
			break
		}
		c.gStats.cnts.Add(c.gStats.hRdBytes, counters.Val(n))

	skip_read:
		rpos += n
		missing -= n
		if missing <= 0 {
			mHdr, _, missing, err = ParseIPFIXmsgHdr(buf[:rpos], 0)
			if err != nil {
				if err == ErrIPFIXmoreBytes {
					if missing == 0 {
						BUG("acme ipfix: more bytes error but 0-missing\n")
						c.gStats.cnts.Inc(c.gStats.hBUG)
						return // exit
					}
					c.gStats.cnts.Inc(c.gStats.hShortRead)
					continue
				} else {
					ERR("acme ipfix: unrecoverable error %s on %s %s\n",
						err, c.conn.RemoteAddr(), c.conn.LocalAddr())
					c.gStats.cnts.Inc(c.gStats.hPktParseErr)
					return // exit
				}
			}
			if int(mHdr.Length) > rpos {
				// not whole message yet
				missing = int(mHdr.Length) - rpos
				c.gStats.cnts.Inc(c.gStats.hShortRead)
				continue
			}
			end = int(mHdr.Length) // end of current message
			// read at least a whole packet
			c.gStats.cnts.Inc(c.gStats.hRdPkts)
			err = c.handlePkt(mHdr, buf[:end])
			// check error and close connection if needed
			if err != nil {
				ERR("acme ipfix: parsing error on %s %s: %s\n",
					c.conn.RemoteAddr(), c.conn.LocalAddr(), err)
				c.gStats.cnts.Inc(c.gStats.hPktParseErr)
				err = nil
				// ignore packet, but keep connection open
			}
			// reset buffer
			missing = 0
			n = copy(buf[:], buf[end:rpos])
			rpos = 0 // n will be added to it in skip_read
			if n > 0 {
				c.gStats.cnts.Inc(c.gStats.hLongRead)
				goto skip_read
			}
		}
	} // for
}

func (c *AcmeIPFIXconn) handlePkt(pktHdr IPFIXmsgHdr, buf []byte) error {
	pos := IPFIXmsgHdrLen
	setsNo := 0

	for pos < len(buf) {
		setHdr, nxt, missing, err := ParseIPFIXsetHdr(buf, pos)
		if err != nil {
			ERR("acme ipfix: set header error: %s, missing %d\n", err, missing)
			c.gStats.cnts.Inc(c.gStats.hPktParseErr)
			return err
		}
		if int(setHdr.Length)+pos > len(buf) {
			ERR("acme ipfix: set header error: invalid length %d (data %d)\n",
				setHdr.Length, len(buf))
			c.gStats.cnts.Inc(c.gStats.hPktParseErr)
			return ErrIPFIXmoreBytes
		}
		setOffs := nxt // pos + IPFIXsetHdrLen
		endOffs := pos + int(setHdr.Length)
		set := buf[setOffs:endOffs]
		switch setHdr.SetID {
		case AcmeIPFIXkeepAlive:
			// TODO: reset keep alive timer
			c.gStats.cnts.Inc(c.gStats.hKeepAlive)

		case AcmeIPFIXconnectReq:
			err = c.handleConnReq(pktHdr, setHdr, set)
		case AcmeIPFIXsipUDP4In, AcmeIPFIXsipUDP4Out:
			err = c.handleSIPudp4(setHdr.SetID, set)
		case AcmeIPFIXsipTCP4In, AcmeIPFIXsipTCP4Out:
			err = c.handleSIPtcp4(setHdr.SetID, set)
		case IPFIXtemplateID:
			WARN("acme ipfix: unexpected template set (%d)\n", setHdr.SetID)
			c.gStats.cnts.Inc(c.gStats.hTemplateSet)
		case IPFIXoptionsTemplateID:
			WARN("acme ipfix: unexpected options template set (%d)\n", setHdr.SetID)
			c.gStats.cnts.Inc(c.gStats.hOptionsTemplateSet)
		default:
			DBG("acme ipfix: unknown/undhandled set type %d\n", setHdr.SetID)
			c.gStats.cnts.Inc(c.gStats.hUnknownSet)
		}
		if err != nil {
			// unrecoverable error
			c.gStats.cnts.Inc(c.gStats.hPktParseErr)
			return err
		}
		pos = endOffs
		setsNo++
	}
	c.gStats.cnts.Set(c.gStats.hMaxSetsPkt, counters.Val(setsNo))
	return nil
}

func (c *AcmeIPFIXconn) handleConnReq(pktHdr IPFIXmsgHdr, sHdr IPFIXsetHdr,
	buf []byte) error {

	const MaxConnReplySize int = IPFIXmsgHdrLen + IPFIXsetHdrLen +
		AcmeIPFIXConnectSetMinLen + 255 /* max hostname */

	var cSet AcmeIPFIXconnectSet
	var pkt [MaxConnReplySize]byte

	c.gStats.cnts.Inc(c.gStats.hConnReq)

	nxt, missing, err := ParseAcmeIPFIXconnectSet(buf, 0, &cSet)
	if err != nil {
		ERR("acme ipfix: connect set parsing failed: %s\n", err)
		return err
	}
	if missing != 0 {
		BUG("acme ipfix: connect set  returned missing %d\n", missing)
		c.gStats.cnts.Inc(c.gStats.hBUG)
	}
	if nxt < len(buf) {
		DBG("acme ipfix: connect set extra padding %d bytes\n", len(buf)-nxt)
		c.gStats.cnts.Set(c.gStats.hMaxPadding, counters.Val(len(buf)-nxt))
		c.gStats.cnts.Inc(c.gStats.hPaddedSets)
	}
	DBG("acme ipfix: connect open request: %v\n", cSet)

	// TODO: lock protecting keepAlive & hname ?
	c.keepAlive = cSet.KeepAliveT
	// save hostname
	c.hnameLen = uint8(copy(c.hname[:], cSet.HostName))

	// reply to connect request
	cSet.CfgFlags = 0 // sip only
	cSet.CfgFlags2 = 0
	cSet.SysFlags = 0
	/*
		cSet.CfgFlags &= ^AcmeIPFIXConnCompressF // disable compression
		// disable everything besides sip
		cSet.CfgFlags &= ^(AcmeIPFIXConnRTPQoSF | AcmeIPFIXConnRTCPStatsF |
			AcmeIPFIXConnOtherStatsF | AcmeIPFIXConnEnumF |
			AcmeIPFIXConnDNSF | AcmeIPFIXConnLDAPF)
	*/
	if (int(sHdr.Length) - IPFIXsetHdrLen) > len(buf) {
		BUG("acme ipfix: passed set length (%d) > buf size (%d)\n",
			int(sHdr.Length)-IPFIXsetHdrLen, len(buf))
		c.gStats.cnts.Inc(c.gStats.hBUG)
		return ErrIPFIXbug
	}

	respLen := IPFIXmsgHdrLen + IPFIXsetHdrLen + AcmeIPFIXConnectSetMinLen +
		len(cSet.HostName)
	if respLen > len(pkt) || respLen > 65535 {
		BUG("acme ipfix: connect answer too big (hostname len %d)\n",
			len(cSet.HostName))
		c.gStats.cnts.Inc(c.gStats.hBUG)
		return ErrIPFIXbug
	}
	// write response pkt header
	binary.BigEndian.PutUint16(pkt[0:2], pktHdr.Version)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(respLen))
	binary.BigEndian.PutUint32(pkt[4:8], pktHdr.ExportTime)
	binary.BigEndian.PutUint32(pkt[8:12], pktHdr.SequenceNo)
	binary.BigEndian.PutUint32(pkt[12:16], pktHdr.ObsDomainId)

	// write response set header
	binary.BigEndian.PutUint16(pkt[16:18], AcmeIPFIXconnectAck) // SetID
	binary.BigEndian.PutUint16(pkt[18:20], uint16(respLen-IPFIXmsgHdrLen))

	// write response data set
	var n, start, end int
	end, err = WriteAcmeIPFIXconnectSet(&cSet, pkt[:], 21)
	if err != nil {
		BUG("acme ipfix: failed to create probe response header: %s\n", err)
		c.gStats.cnts.Inc(c.gStats.hBUG)
		return err
	}
	for start < end {
		n, err = c.conn.Write(pkt[start:end])
		c.gStats.cnts.Add(c.gStats.hWrBytes, counters.Val(n))
		start += n
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				// connection was closed by us  or peer => clean exit
				// NOTE: net.ErrClosed available since go 1.16
				break
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				// TODO: handle deadline - set new one or exit
				ERR("acme ipfix: connection deadline on write\n")
				return err // exit
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				WARN("acme ipfix: temporary write error on %s %s: %s\n",
					c.conn.RemoteAddr(), c.conn.LocalAddr(), ne)
				continue
			}
			ERR("acme ipfix: unrecoverable write error  on %s %s: %s\n",
				c.conn.RemoteAddr(), c.conn.LocalAddr(), err)
			return err
		}
		c.gStats.cnts.Inc(c.gStats.hWrPkts)
		break
	}
	return err
}

func (c *AcmeIPFIXconn) handleSIPudp4(setID uint16, buf []byte) error {

	var udp4InSet AcmeIPFIXsipUDP4InSet
	var udp4OutSet AcmeIPFIXsipUDP4OutSet
	var msg []byte
	var nxt, missing int
	var err error

	c.pktNo++
	switch setID {
	case AcmeIPFIXsipUDP4In:
		c.gStats.cnts.Inc(c.gStats.hSIPudp4In)
		nxt, missing, err = ParseAcmeIPFIXsipUDP4InSet(buf, 0, &udp4InSet)
		msg = udp4InSet.Msg
	case AcmeIPFIXsipUDP4Out:
		c.gStats.cnts.Inc(c.gStats.hSIPudp4Out)
		nxt, missing, err = ParseAcmeIPFIXsipUDP4OutSet(buf, 0, &udp4OutSet)
		msg = udp4OutSet.Msg
	default:
		BUG("acme ipfix: handle sip udp template called with %d\n", setID)
		c.gStats.cnts.Inc(c.gStats.hBUG)
		return ErrIPFIXbug
	}
	if err != nil {
		ERR("acme ipfix: udp4 set %d parsing failed: %s\n", setID, err)
		return err
	}
	if missing != 0 {
		BUG("acme ipfix: udp4 set  returned missing %d\n", missing)
		c.gStats.cnts.Inc(c.gStats.hBUG)
	}
	if nxt < len(buf) {
		DBG("acme ipfix: udp4 set extra padding %d bytes\n", len(buf)-nxt)
		c.gStats.cnts.Set(c.gStats.hMaxPadding, counters.Val(len(buf)-nxt))
		c.gStats.cnts.Inc(c.gStats.hPaddedSets)
	}
	if setID == AcmeIPFIXsipUDP4In {
		DBG("acme ipfix: sip udp4 ingress set (msg len %d)\n",
			len(udp4InSet.Msg))
	} else {
		DBG("acme ipfix: sip udp4 egress set (callid in: %q, msg len %d)\n",
			udp4OutSet.CallId, len(udp4OutSet.Msg))
	}

	// get ipv4 && udp headers
	var ip4 layers.IPv4
	var udp layers.UDP

	err = ip4.DecodeFromBytes(msg, gopacket.NilDecodeFeedback)
	if err != nil {
		ERR("acme ipfix: sip udp4: bad ipv4 header: %s\n", err)
		return err
	}
	err = udp.DecodeFromBytes(ip4.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		ERR("acme ipfix: sip udp4: bad udp header: %s\n", err)
		return err
	}
	if !nonSIP(udp.Payload, ip4.SrcIP, int(udp.SrcPort),
		ip4.DstIP, int(udp.DstPort)) {

		udpSIPMsg(ioutil.Discard, &c.sipmsg, udp.Payload, c.pktNo,
			ip4.SrcIP, int(udp.SrcPort),
			ip4.DstIP, int(udp.DstPort), false)
	} else {
		// not sip -> probe
		pktErrEvHandler(calltr.EvNonSIPprobe,
			ip4.SrcIP, int(udp.SrcPort),
			ip4.DstIP, int(udp.DstPort),
			calltr.NProtoUDP, nil, nil)
	}
	return nil
}

func (c *AcmeIPFIXconn) handleSIPtcp4(setID uint16, buf []byte) error {
	var tcp4InSet AcmeIPFIXsipTCP4InSet
	var tcp4OutSet AcmeIPFIXsipTCP4OutSet
	var smsg []byte
	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var nxt, missing int
	var err error

	c.pktNo++
	switch setID {
	case AcmeIPFIXsipTCP4In:
		c.gStats.cnts.Inc(c.gStats.hSIPtcp4In)
		nxt, missing, err = ParseAcmeIPFIXsipTCP4InSet(buf, 0, &tcp4InSet)
		smsg = tcp4InSet.SipMsg
		srcIP = tcp4InSet.SrcIP
		srcPort = tcp4InSet.SrcPort
		dstIP = tcp4InSet.DstIP
		dstPort = tcp4InSet.DstPort
	case AcmeIPFIXsipTCP4Out:
		c.gStats.cnts.Inc(c.gStats.hSIPtcp4Out)
		nxt, missing, err = ParseAcmeIPFIXsipTCP4OutSet(buf, 0, &tcp4OutSet)
		smsg = tcp4OutSet.SipMsg
		srcIP = tcp4OutSet.SrcIP
		srcPort = tcp4OutSet.SrcPort
		dstIP = tcp4OutSet.DstIP
		dstPort = tcp4OutSet.DstPort
	default:
		BUG("acme ipfix: handle sip tcp template called with %d\n", setID)
		c.gStats.cnts.Inc(c.gStats.hBUG)
		return ErrIPFIXbug
	}
	if err != nil {
		ERR("acme ipfix: tcp4 set %d parsing failed: %s\n", setID, err)
		return err
	}
	if missing != 0 {
		BUG("acme ipfix: tcp4 set  returned missing %d\n", missing)
		c.gStats.cnts.Inc(c.gStats.hBUG)
	}
	if nxt < len(buf) {
		DBG("acme ipfix: tcp4 set extra padding %d bytes\n", len(buf)-nxt)
		c.gStats.cnts.Set(c.gStats.hMaxPadding, counters.Val(len(buf)-nxt))
		c.gStats.cnts.Inc(c.gStats.hPaddedSets)
	}
	if setID == AcmeIPFIXsipTCP4In {
		DBG("acme ipfix: sip tcp4 ingress set (sip msg len %d)\n",
			len(tcp4InSet.SipMsg))
	} else {
		DBG("acme ipfix: sip tcp4 egress set (callid in: %q, msg len %d)\n",
			tcp4OutSet.CallId, len(tcp4OutSet.SipMsg))
	}

	if nonSIP(smsg, srcIP, int(srcPort), dstIP, int(dstPort)) {
		// not sip -> probe
		pktErrEvHandler(calltr.EvNonSIPprobe,
			srcIP, int(srcPort),
			dstIP, int(dstPort),
			calltr.NProtoTCP, nil, nil)
		return nil
	}
	// parse sip msg
	c.sipmsg.Reset()
	// don't allow messages without Content-Length?
	o, errParse := sipsp.ParseSIPMsg(smsg, 0, &c.sipmsg,
		sipsp.SIPMsgNoMoreDataF|sipsp.SIPMsgSkipBodyF|sipsp.SIPMsgCLenReqF)
	switch errParse {
	case 0:
		// stats & dbg
		stats.Inc(sCnts.ok)
		stats.Inc(sCnts.sipTCP)
		if c.sipmsg.FL.Request() {
			stats.Inc(sCnts.reqsN)
			stats.Inc(sCnts.method[c.sipmsg.FL.MethodNo])
		} else {
			stats.Inc(sCnts.replsN)
			if c.sipmsg.FL.Status < 1000 {
				stats.Inc(sCnts.repl[c.sipmsg.FL.Status/100])
			}
		}

		var endPoints [2]calltr.NetInfo
		endPoints[0].SetProto(calltr.NProtoTCP)
		endPoints[1].SetProto(calltr.NProtoTCP)
		endPoints[0].SetIP(srcIP)
		endPoints[0].Port = srcPort
		endPoints[1].SetIP(dstIP)
		endPoints[1].Port = dstPort
		ok := CallTrack(&c.sipmsg, endPoints)
		if ok {
			stats.Inc(sCnts.callTrTCP)
		} else {
			/*
			   if s.Verbose &&
			       (Plog.L(slog.LERR) || s.W != ioutil.Discard) {
			       Plog.LogMux(s.W, true, slog.LERR,
			           "ERROR: tcp CallTrack failed\n")
			   }
			*/
			ERR("ipfix tcp: CallTrack failed\n")
			stats.Inc(sCnts.callTrErrTCP)
		}
		if o != len(smsg) {
			stats.Inc(sCnts.offsetErr)
			DBG("ipfix tcp: unexpected offset after parsing => %d / %d\n",
				o, len(smsg))
			if int(c.sipmsg.Body.Len+c.sipmsg.Body.Offs) != len(buf) {
				stats.Inc(sCnts.bodyErr)
				DBG("ipfix tcp: clen: %d, actual body len %d, body end %d\n",
					c.sipmsg.PV.CLen.UIVal, int(c.sipmsg.Body.Len),
					int(c.sipmsg.Body.Len+c.sipmsg.Body.Offs))
			}
		}
	case sipsp.ErrHdrNoCLen:
		stats.Inc(sCnts.errs)
		stats.Inc(sCnts.errsTCP)
		stats.Inc(sCnts.errType[errParse])
		stats.Inc(sCnts.bodyErr)
		/*
		   if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
		       Plog.LogMux(s.W, true, slog.LNOTICE,
		           "tcp: missing Content-Length Header: %s\n", errParse)
		   }
		*/
		DBG("ipfix tcp: missing Content-Length Header: %s\n", errParse)
		// parse error event
		pktErrEvHandler(calltr.EvParseErr,
			srcIP, int(srcPort), dstIP, int(dstPort),
			calltr.NProtoTCP,
			c.sipmsg.PV.GetCallID().CallID.Get(smsg),
			[]byte("missing Content-Length"))

	default: /* handles sipsp.ErrHdrMoreBytes too */
		// stats + dbg
		stats.Inc(sCnts.errs)
		stats.Inc(sCnts.errsTCP)
		stats.Inc(sCnts.errType[errParse])
		/*
		   if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
		       Plog.LogMux(s.W, true, slog.LNOTICE,
		           "tcp: unexpected error after parsing "+
		               "stream sync lost for %p => %s\n", s, errParse)
		       Plog.LogMux(s.W, true, slog.LNOTICE,
		           "parsed ok:\n%q\n",
		           s.buf[s.mstart:s.mstart+o])
		       fmt.Fprintln(s.W)
		   } else if errParse == sipsp.ErrHdrBug ||
		       errParse == sipsp.ErrConvBug {
		       // show parsing bug always
		       Plog.BUG("unexpected error after parsing => %s ,"+
		           " parsed ok:\n%q\n", errParse,
		           s.buf[s.mstart:s.mstart+o])
		   }
		*/
		if o < len(smsg) {
			l := o + 40 // error message, first 40 bytes
			if l > len(smsg) {
				l = len(smsg)
			}
			/*
			   if Plog.L(slog.LNOTICE) || s.W != ioutil.Discard {
			       Plog.LogMux(s.W, true, slog.LNOTICE,
			           "error before:\n%q\n", s.buf[s.mstart+o:l])
			   }
			*/
			DBG("ipfix tcp: error before:\n%q\n", smsg[:l])
		}
		// parse error event
		rep := o
		if rep > len(smsg) {
			rep = len(smsg)
		}
		// report first 60 parsed ok chars from the message
		if rep > 60 {
			rep = 60
		}
		pktErrEvHandler(calltr.EvParseErr,
			srcIP, int(srcPort), dstIP, int(dstPort),
			calltr.NProtoTCP,
			c.sipmsg.PV.GetCallID().CallID.Get(smsg),
			smsg[:rep])
	}
	/* don't return err here: if it's a sip message parsing error
	   we can just ignore the ipfix set, we don't need to close the
	   connection */
	return nil
}
