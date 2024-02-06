package sipcallmon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/timestamp"
)

var ErrAcmeIPFIXbadIPhdrVer = errors.New("invalid IP header version")

// AcmeIPFIXconnInfo contains a copy of the interesting parts
// of AcmeIPFIXconn struct.
type AcmeIPFIXconnInfo struct {
	Id          uint64
	Src         calltr.NetInfo
	Dst         calltr.NetInfo
	StartTS     timestamp.TS
	LastIO      timestamp.TS
	Timeout     int32
	PktNo       uint64
	SIPpktNo    uint64
	HandshakeNo uint32
	Handshake   AcmeIPFIXconnectSet // handshake info (probe connect)
	KeepAlive   uint16
	hname       [255]byte
}

func (c *AcmeIPFIXconnInfo) String() string {
	s := fmt.Sprintf("%s:%d -> %s:%d   id:%5d,  pkts:%6d,  sip:%6d",
		c.Src.IP(), c.Src.Port, c.Dst.IP(), c.Dst.Port,
		c.Id, c.PktNo, c.SIPpktNo)
	return s
}

type AcmeIPFIXconnCfg struct {
	TimeoutMin int
	TimeoutMax int
}

type AcmeIPFIXconn struct {
	id       uint64
	conn     net.TCPConn
	startTS  timestamp.TS
	lastIO   timestamp.TS
	timeout  atomic.Int32 // io timeout in s
	pktNo    atomic.Uint64
	sipPktNo atomic.Uint64
	sipmsg   sipsp.PSIPMsg  // avoids allocs
	sipHdrs  [100]sipsp.Hdr // extra space for sip headers (needed for msg sig)

	gStats    *acmeIPFIXstatsT // global stats (must be init)
	hshkLock  sync.Mutex
	hshkNo    uint32              // handshake number
	hshkInfo  AcmeIPFIXconnectSet // handshake info (probe connect)
	keepAlive uint16              // negotiated/replied KeepAlive value
	hname     [255]byte           // hostname buffer
	Cfg       AcmeIPFIXconnCfg

	next, prev *AcmeIPFIXconn
}

func (c *AcmeIPFIXconn) Reset() {
	*c = AcmeIPFIXconn{}
}

func (c *AcmeIPFIXconn) GetInfo(info *AcmeIPFIXconnInfo) {
	info.Id = c.id
	src := c.conn.RemoteAddr().(*net.TCPAddr)
	dst := c.conn.LocalAddr().(*net.TCPAddr)
	info.Src.SetProto(calltr.NProtoTCP)
	info.Src.SetIP(src.IP)
	info.Src.Port = uint16(src.Port)
	info.Dst.SetProto(calltr.NProtoTCP)
	info.Dst.SetIP(dst.IP)
	info.Dst.Port = uint16(dst.Port)
	info.StartTS = c.startTS // not changing so no need for atomic
	info.LastIO = timestamp.AtomicLoad(&c.lastIO)
	info.Timeout = c.timeout.Load()
	info.PktNo = c.pktNo.Load()
	info.SIPpktNo = c.sipPktNo.Load()
	// copy handshake info
	c.hshkLock.Lock()
	{
		copy(info.hname[:], c.hshkInfo.HostName)
		info.Handshake = c.hshkInfo
		info.HandshakeNo = c.hshkNo
		info.KeepAlive = c.keepAlive
	}
	c.hshkLock.Unlock()
}

// common timeout handling, returns nil if no timeout, else the passed error.
func (c *AcmeIPFIXconn) handleIOdeadline(e error) error {
	c.gStats.cnts.Inc(c.gStats.hIOdeadline)
	// handle deadline: check if time from last io
	//  exceeds timeout and if so => error, else extend
	//  deadline.
	crtTimeout := int(c.timeout.Load())
	if crtTimeout <= 0 {
		// io timeouts disabled
		return nil
	}
	lastIO := timestamp.AtomicLoad(&c.lastIO)
	if timestamp.Now().Sub(lastIO) <=
		time.Duration(crtTimeout)*time.Second {
		// less then timeout seconds since last IO
		e := c.conn.SetDeadline(lastIO.Add(
			time.Duration(crtTimeout) * time.Second).Time())
		if e != nil {
			ERR("SetDeadline (%s) failed with %q\n",
				lastIO.Add(time.Duration(crtTimeout)*time.Second).Time(),
				e)
			c.gStats.cnts.Inc(c.gStats.hErrOther)
		}
		return nil
	}
	return e
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
	// initial timeout
	timeout := c.Cfg.TimeoutMax
	if timeout <= 0 {
		timeout = c.Cfg.TimeoutMin
	}
	if timeout > 0 {
		c.timeout.Store(int32(timeout))
		if e := c.conn.SetDeadline(
			time.Now().Add(time.Duration(timeout) * time.Second)); e != nil {
			ERR("SetDeadline (%s) failed with %q\n",
				time.Now().Add(time.Duration(timeout)*time.Second), e)
			c.gStats.cnts.Inc(c.gStats.hErrOther)
		}
	}

	for {
		n, err = c.conn.Read(buf[rpos:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				// connection was closed by us => clean exit
				// NOTE: net.ErrClosed available since go 1.16
				DBG("connection closed by us or EOF: %s\n", err)
				break
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				if c.handleIOdeadline(err) == nil {
					continue
				}
				// else timeout exceeded
				ERR("acme ipfix: connection io timeout exceeded (%d/%d)"+
					" on read\n",
					timestamp.Now().Sub(
						timestamp.AtomicLoad(&c.lastIO))/time.Second,
					c.timeout.Load())
				c.gStats.cnts.Inc(c.gStats.hTimeoutErr)
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
		timestamp.AtomicStore(&c.lastIO, timestamp.Now())
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
			c.pktNo.Add(1)
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
			//  receiving something automatically resets the io timeout
			// (nothing to do here)
			c.gStats.cnts.Inc(c.gStats.hKeepAlive)

		case AcmeIPFIXconnectReq:
			err = c.handleConnReq(pktHdr, setHdr, set)
		case AcmeIPFIXsipUDP4In, AcmeIPFIXsipUDP4Out:
			err = c.handleSIPudp(setHdr.SetID, set)
		case AcmeIPFIXsipTCP4In, AcmeIPFIXsipTCP4Out:
			err = c.handleSIPtcp4(setHdr.SetID, set)
		// missing: UDP6In, UDP6Out (same as ID & format as UPD4?)
		// missing: TCP6In & TCP6Out (unknown ID & format)
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
	timeout := 2 * int(cSet.KeepAliveT) // new I/O timeout, 2* req. keepalive
	if c.Cfg.TimeoutMin > 0 && timeout < c.Cfg.TimeoutMin {
		timeout = c.Cfg.TimeoutMin
	}
	if c.Cfg.TimeoutMax > 0 && timeout > c.Cfg.TimeoutMax {
		timeout = c.Cfg.TimeoutMax
	}
	keepAlive := timeout / 2
	if keepAlive == 0 && timeout != 0 {
		keepAlive = 1           // timeout < 2, but 2 is min.
		timeout = 2 * keepAlive // min. timeout
	}
	oldTimeout := c.timeout.Swap(int32(timeout))

	c.hshkLock.Lock()
	{
		c.keepAlive = uint16(keepAlive)
		// save hostname
		l := copy(c.hname[:], cSet.HostName)
		c.hshkInfo = cSet
		c.hshkInfo.HostName = c.hname[:l] // fix HostName slice
		c.hshkNo++
	}
	c.hshkLock.Unlock()

	// reply to connect request
	cSet.KeepAliveT = uint16(keepAlive)
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

	// set new timeout after handshake
	if int(oldTimeout) != timeout {
		if timeout > 0 {
			e := c.conn.SetDeadline(time.Now().Add(
				time.Duration(timeout) * time.Second))
			if e != nil {
				ERR("SetDeadline (%s) failed with %q\n",
					time.Now().Add(time.Duration(timeout)*time.Second),
					e)
				c.gStats.cnts.Inc(c.gStats.hErrOther)
			}
		}
	}

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
				if c.handleIOdeadline(err) == nil {
					continue
				}
				// else timeout exceeded
				ERR("acme ipfix: connection io timeout exceeded (%d/%d)"+
					" on write\n",
					timestamp.Now().Sub(
						timestamp.AtomicLoad(&c.lastIO))/time.Second,
					c.timeout.Load())
				c.gStats.cnts.Inc(c.gStats.hTimeoutErr)
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
		timestamp.AtomicStore(&c.lastIO, timestamp.Now())
		c.gStats.cnts.Inc(c.gStats.hWrPkts)
		break
	}
	return err
}

// handleSIPudp  handles IPv4 and IPv6 UDP ingress and egress datasets.
// Note: we suppose the IPv6 UDP is the same format as IPv4, but
//
//	there is no confirmation for that.
func (c *AcmeIPFIXconn) handleSIPudp(setID uint16, buf []byte) error {

	var udp4InSet AcmeIPFIXsipUDP4InSet
	var udp4OutSet AcmeIPFIXsipUDP4OutSet
	var msg []byte
	var nxt, missing int
	var err error

	c.sipPktNo.Add(1)
	switch setID {
	case AcmeIPFIXsipUDP4In:
		nxt, missing, err = ParseAcmeIPFIXsipUDP4InSet(buf, 0, &udp4InSet)
		msg = udp4InSet.Msg
	case AcmeIPFIXsipUDP4Out:
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
	var ipPayload []byte
	var srcIP, dstIP net.IP

	// try to handle IPv6 too (hopefully the same format is used as
	// for IPv4)
	ipVersion := uint8(msg[0]) >> 4
	switch ipVersion {
	case 4:
		if setID == AcmeIPFIXsipUDP4In {
			c.gStats.cnts.Inc(c.gStats.hSIPudp4In)
		} else {
			c.gStats.cnts.Inc(c.gStats.hSIPudp4Out)
		}
		var ip4 layers.IPv4
		err = ip4.DecodeFromBytes(msg, gopacket.NilDecodeFeedback)
		if err != nil {
			ERR("acme ipfix: sip udp4: bad ipv4 header: %s\n", err)
			return err
		}
		if ip4.Version != 4 {
			ERR("acme ipfix: sip udp4: invalid ipv4 header version: %d\n",
				ip4.Version)
			return ErrAcmeIPFIXbadIPhdrVer
		}
		srcIP = ip4.SrcIP
		dstIP = ip4.DstIP
		ipPayload = ip4.Payload
	case 6:
		if setID == AcmeIPFIXsipUDP4In { // suppose the same template is used
			c.gStats.cnts.Inc(c.gStats.hSIPudp6In)
		} else {
			c.gStats.cnts.Inc(c.gStats.hSIPudp6Out)
		}
		var ip6 layers.IPv6
		err = ip6.DecodeFromBytes(msg, gopacket.NilDecodeFeedback)
		if err != nil {
			ERR("acme ipfix: sip udp6: bad ipv6 header: %s\n", err)
			return err
		}
		if ip6.Version != 6 {
			ERR("acme ipfix: sip udp6: invalid ipv6 header version: %d\n",
				ip6.Version)
			return ErrAcmeIPFIXbadIPhdrVer
		}
		srcIP = ip6.SrcIP
		dstIP = ip6.DstIP
		ipPayload = ip6.Payload
	default:
		ERR("acme ipfix: sip udp: invalid ip header version: %d\n",
			ipVersion)
		return ErrAcmeIPFIXbadIPhdrVer
	}

	// parse udp header
	var udp layers.UDP
	err = udp.DecodeFromBytes(ipPayload, gopacket.NilDecodeFeedback)
	if err != nil {
		ERR("acme ipfix: sip udp4: bad udp header: %s\n", err)
		return err
	}
	if !nonSIP(udp.Payload, srcIP, int(udp.SrcPort),
		dstIP, int(udp.DstPort)) {

		udpSIPMsg(ioutil.Discard, &c.sipmsg, udp.Payload, c.pktNo.Load(),
			srcIP, int(udp.SrcPort),
			dstIP, int(udp.DstPort), false)
	} else {
		// not sip -> probe
		pktErrEvHandler(calltr.EvNonSIPprobe,
			srcIP, int(udp.SrcPort),
			dstIP, int(udp.DstPort),
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

	c.sipPktNo.Add(1)
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
