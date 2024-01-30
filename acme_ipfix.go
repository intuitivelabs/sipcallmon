package sipcallmon

import (
	"encoding/binary"
	"net"
)

const (
	AcmeIPFIXkeepAlive   uint16 = 0 // proprietary
	AcmeIPFIXconnectReq  uint16 = 256
	AcmeIPFIXconnectAck  uint16 = 257
	AcmeIPFIXsipUDP4In   uint16 = 258
	AcmeIPFIXsipUDP4Out  uint16 = 259
	AcmeIPFIXsipTCP4In   uint16 = 260
	AcmeIPFIXsipTCP4Out  uint16 = 261
	AcmeIPFIXsipSCTP4In  uint16 = 262
	AcmeIPFIXsipSCTP4Out uint16 = 263
)

// flags used in the connect and connect ack messages / data sets
// to request or show support for different data sets
const (
	AcmeIPFIXConnErrorF      uint8 = 0x01
	AcmeIPFIXConnCompressF   uint8 = 0x02 // reset to disallow compression
	AcmeIPFIXConnRTPQoSF     uint8 = 0x04 // set for RTP QoS stats
	AcmeIPFIXConnRTCPStatsF  uint8 = 0x08 // set for RTCP stats
	AcmeIPFIXConnOtherStatsF uint8 = 0x10
	AcmeIPFIXConnEnumF       uint8 = 0x20 // set for ENUM
	AcmeIPFIXConnDNSF        uint8 = 0x40 // set for DNS
	AcmeIPFIXConnLDAPF       uint8 = 0x80 // set for LDAP
)

const AcmeIPFIXConnectSetMinLen int = 22

type AcmeIPFIXconnectSet struct {
	MajorVer   uint16 // major protocol version == 1
	MinorVer   uint16 // minor protocol version
	CfgFlags   uint16
	CfgFlags2  uint16
	SysFlags   uint16
	KeepAliveT uint16 // keep alive interval in s, 0 for disabled
	SysID      uint32

	ProdCode1    uint8 // system version product code1
	ProdCode2    uint8 // system version product code2
	ProdMajorVer uint8 // system version product major version
	ProdMinorVer uint8 // system version product minor version
	Revision     uint8

	HostNameLen uint8
	HostName    []byte
}

// ParseAcmeIPFIXconnectSet parses the handshake messages uses by
// Acme/Oracle SBCs (proprietary extension).
// It returns a new offset after the parsed set (a new set might start
// at it), how many bytes are still needed if buf was too small to parse
// the whole message and an error (nil on success, ErrIPFIXmoreBytes if
// buf was too small)
func ParseAcmeIPFIXconnectSet(buf []byte, offs int, s *AcmeIPFIXconnectSet) (int, int, error) {

	data := buf[offs:]
	if len(data) < AcmeIPFIXConnectSetMinLen {
		return offs, AcmeIPFIXConnectSetMinLen - len(data), ErrIPFIXmoreBytes
	}

	s.MajorVer = binary.BigEndian.Uint16(data[0:2])
	s.MinorVer = binary.BigEndian.Uint16(data[2:4])
	s.CfgFlags = binary.BigEndian.Uint16(data[4:6])
	s.CfgFlags2 = binary.BigEndian.Uint16(data[6:8])
	s.SysFlags = binary.BigEndian.Uint16(data[8:10])
	s.KeepAliveT = binary.BigEndian.Uint16(data[10:12])
	s.SysID = binary.BigEndian.Uint32(data[12:16])

	s.ProdCode1 = data[16]
	s.ProdCode2 = data[17]
	s.ProdMajorVer = data[18]
	s.ProdMinorVer = data[19]
	s.Revision = data[20]

	s.HostNameLen = data[21]
	if s.HostNameLen == 0xff { // length >= 255 for hostname not supported
		return offs + AcmeIPFIXConnectSetMinLen, 0, ErrIPFIXinvLen
	}

	if (AcmeIPFIXConnectSetMinLen + int(s.HostNameLen)) > len(data) {
		// not enough space to get the hostname
		return offs,
			(AcmeIPFIXConnectSetMinLen + int(s.HostNameLen)) - len(data),
			ErrIPFIXmoreBytes
	}
	s.HostName = data[22 : 22+s.HostNameLen]
	return offs + AcmeIPFIXConnectSetMinLen + int(s.HostNameLen), 0, nil
}

// returns new offset in dstBuf after writing AcmeIPFIXConnectSet and
// an error (nil on success, ErrIPFIXMoreBytes if dstBuf[offs:] is too
// small ...)
func WriteAcmeIPFIXconnectSet(s *AcmeIPFIXconnectSet, dstBuf []byte, offs int) (int, error) {
	dst := dstBuf[offs:]
	tlen := AcmeIPFIXConnectSetMinLen + len(s.HostName)
	if tlen > len(dst) {
		return 0, ErrIPFIXmoreBytes
	}
	if len(s.HostName) <= 0xff {
		return 0, ErrIPFIXinvLen
	}
	binary.BigEndian.PutUint16(dst[0:], s.MajorVer)
	binary.BigEndian.PutUint16(dst[2:], s.MinorVer)
	binary.BigEndian.PutUint16(dst[4:], s.CfgFlags)
	binary.BigEndian.PutUint16(dst[6:], s.CfgFlags2)
	binary.BigEndian.PutUint16(dst[8:], s.SysFlags)
	binary.BigEndian.PutUint16(dst[10:], s.KeepAliveT)
	binary.BigEndian.PutUint32(dst[12:], s.SysID)

	dst[16] = s.ProdCode1
	dst[17] = s.ProdCode2
	dst[18] = s.ProdMajorVer
	dst[19] = s.ProdMinorVer
	dst[20] = s.Revision

	dst[21] = uint8(len(s.HostName))
	copy(dst[22:], s.HostName)
	return offs + tlen, nil
}

const AcmeIPFIXsipUDP4InSetMinLen int = 12 + 1 // 0-length message

type AcmeIPFIXsipUDP4InSet struct {
	TimeS  uint32
	TimeUS uint32
	IfSlot uint8 // interface slot
	IfPort uint8 // interface port
	VlanID uint16

	Length1 uint8  // first by of lenght, 0xff if length in length2
	Length2 uint16 // 0 if length1 < 0xff (length is in Length1)
	Msg     []byte // IP+UDP+SIP message, points inside the parsed data

}

func ParseAcmeIPFIXsipUDP4InSet(buf []byte, offs int,
	s *AcmeIPFIXsipUDP4InSet) (int, int, error) {

	data := buf[offs:]
	if len(data) < AcmeIPFIXsipUDP4InSetMinLen {
		return offs,
			AcmeIPFIXsipUDP4InSetMinLen - len(data), ErrIPFIXmoreBytes
	}

	s.TimeS = binary.BigEndian.Uint32(data[0:4])
	s.TimeUS = binary.BigEndian.Uint32(data[4:8])
	s.IfSlot = data[8]
	s.IfPort = data[9]
	s.VlanID = binary.BigEndian.Uint16(data[10:12])

	s.Length1 = data[12]
	msgStart := 13
	msgLen := int(s.Length1)
	if s.Length1 == 0xff {
		if len(data) < (msgStart + 2) {
			return offs, (msgStart + 2) - len(data), ErrIPFIXmoreBytes
		}
		s.Length2 = binary.BigEndian.Uint16(data[msgStart : msgStart+2])
		msgLen = int(s.Length2)
		msgStart += 2
	} else {
		s.Length2 = 0
	}
	if len(data) < (msgStart + msgLen) {
		return offs, msgStart + msgLen - len(data),
			ErrIPFIXmoreBytes
	}
	s.Msg = data[msgStart : msgStart+msgLen]
	return offs + msgStart + msgLen, 0, nil
}

const AcmeIPFIXsipUDP4OutSetMinLen int = 12 + 1 + 1 // 0-length & call-id msg.

type AcmeIPFIXsipUDP4OutSet struct {
	TimeS  uint32
	TimeUS uint32
	IfSlot uint8 // interface slot
	IfPort uint8 // interface port
	VlanID uint16

	CallIdLen uint8  // call-id, variable length, <= 255
	Length1   uint8  // first by of lenght, 0xff if length in length2
	Length2   uint16 // 0 if length1 < 0xff (length is in Length1)

	CallId []byte // incoming call-id, points inside the parsed data
	Msg    []byte // IP+UDP+SIP message, points inside the parsed data

}

func ParseAcmeIPFIXsipUDP4OutSet(buf []byte, offs int,
	s *AcmeIPFIXsipUDP4OutSet) (int, int, error) {

	data := buf[offs:]
	if len(data) < AcmeIPFIXsipUDP4OutSetMinLen {
		return offs,
			AcmeIPFIXsipUDP4OutSetMinLen - len(data), ErrIPFIXmoreBytes
	}

	s.TimeS = binary.BigEndian.Uint32(data[0:4])
	s.TimeUS = binary.BigEndian.Uint32(data[4:8])
	s.IfSlot = data[8]
	s.IfPort = data[9]
	s.VlanID = binary.BigEndian.Uint16(data[10:12])

	s.CallIdLen = data[12]
	if s.CallIdLen == 0xff {
		return offs, 0, ErrIPFIXinvLen
	}
	nxt := 13 + int(s.CallIdLen)
	if (nxt + 1) > len(data) {
		return offs, (nxt + 1) - len(data), ErrIPFIXmoreBytes
	}
	s.CallId = data[13:nxt]
	s.Length1 = data[nxt]
	msgStart := nxt + 1
	msgLen := int(s.Length1)
	if s.Length1 == 0xff {
		if len(data) < (msgStart + 2) {
			return offs, (msgStart + 2) - len(data), ErrIPFIXmoreBytes
		}
		s.Length2 = binary.BigEndian.Uint16(data[msgStart : msgStart+2])
		msgLen = int(s.Length2)
		msgStart += 2
	} else {
		s.Length2 = 0
	}
	if len(data) < (msgStart + msgLen) {
		return offs, msgStart + msgLen - len(data),
			ErrIPFIXmoreBytes
	}
	s.Msg = data[msgStart : msgStart+msgLen]
	return offs + msgStart + msgLen, 0, nil
}

const AcmeIPFIXsipTCP4InSetMinLen int = 12 + 16 + 1 // 0-length message

type AcmeIPFIXsipTCP4InSet struct {
	TimeS  uint32
	TimeUS uint32
	IfSlot uint8 // interface slot
	IfPort uint8 // interface port
	VlanID uint16

	DstIP   net.IP
	SrcIP   net.IP
	DstPort uint16
	SrcPort uint16
	Context uint32

	Length1 uint8  // first by of lenght, 0xff if length in length2
	Length2 uint16 // 0 if length1 < 0xff (length is in Length1)
	SipMsg  []byte // SIP message, points inside the parsed data

}

func ParseAcmeIPFIXsipTCP4InSet(buf []byte, offs int,
	s *AcmeIPFIXsipTCP4InSet) (int, int, error) {

	data := buf[offs:]
	if len(data) < AcmeIPFIXsipTCP4InSetMinLen {
		return offs,
			AcmeIPFIXsipTCP4InSetMinLen - len(data), ErrIPFIXmoreBytes
	}

	s.TimeS = binary.BigEndian.Uint32(data[0:4])
	s.TimeUS = binary.BigEndian.Uint32(data[4:8])
	s.IfSlot = data[8]
	s.IfPort = data[9]
	s.VlanID = binary.BigEndian.Uint16(data[10:12])

	s.DstIP = data[12:16]
	s.SrcIP = data[16:20]
	s.DstPort = binary.BigEndian.Uint16(data[20:22])
	s.SrcPort = binary.BigEndian.Uint16(data[22:24])
	s.Context = binary.BigEndian.Uint32(data[24:28])

	s.Length1 = data[28]
	msgStart := 29
	msgLen := int(s.Length1)
	if s.Length1 == 0xff {
		if len(data) < (msgStart + 2) {
			return offs, (msgStart + 2) - len(data), ErrIPFIXmoreBytes
		}
		s.Length2 = binary.BigEndian.Uint16(data[msgStart : msgStart+2])
		msgLen = int(s.Length2)
		msgStart += 2
	} else {
		s.Length2 = 0
	}
	if len(data) < (msgStart + msgLen) {
		return offs, msgStart + msgLen - len(data),
			ErrIPFIXmoreBytes
	}
	s.SipMsg = data[msgStart : msgStart+msgLen]
	return offs + msgStart + msgLen, 0, nil
}

const AcmeIPFIXsipTCP4OutSetMinLen int = 12 + 16 + 1 + 1 // 0-len & callid msg.

type AcmeIPFIXsipTCP4OutSet struct {
	TimeS  uint32
	TimeUS uint32
	IfSlot uint8 // interface slot
	IfPort uint8 // interface port
	VlanID uint16

	DstIP   net.IP
	SrcIP   net.IP
	DstPort uint16
	SrcPort uint16
	Context uint32

	CallIdLen uint8  // call-id, variable length, <= 255
	Length1   uint8  // first by of lenght, 0xff if length in length2
	Length2   uint16 // 0 if length1 < 0xff (length is in Length1)

	CallId []byte // incoming call-id, points inside the parsed data
	SipMsg []byte // SIP message, points inside the parsed data
}

func ParseAcmeIPFIXsipTCP4OutSet(buf []byte, offs int,
	s *AcmeIPFIXsipTCP4OutSet) (int, int, error) {

	data := buf[offs:]
	if len(data) < AcmeIPFIXsipTCP4OutSetMinLen {
		return offs,
			AcmeIPFIXsipTCP4OutSetMinLen - len(data), ErrIPFIXmoreBytes
	}

	s.TimeS = binary.BigEndian.Uint32(data[0:4])
	s.TimeUS = binary.BigEndian.Uint32(data[4:8])
	s.IfSlot = data[8]
	s.IfPort = data[9]
	s.VlanID = binary.BigEndian.Uint16(data[10:12])

	s.DstIP = data[12:16]
	s.SrcIP = data[16:20]
	s.DstPort = binary.BigEndian.Uint16(data[20:22])
	s.SrcPort = binary.BigEndian.Uint16(data[22:24])
	s.Context = binary.BigEndian.Uint32(data[24:28])

	s.CallIdLen = data[28]
	if s.CallIdLen == 0xff {
		return offs, 0, ErrIPFIXinvLen
	}
	nxt := 29 + int(s.CallIdLen)
	if (nxt + 1) > len(data) {
		return offs, (nxt + 1) - len(data), ErrIPFIXmoreBytes
	}
	s.CallId = data[29:nxt]
	s.Length1 = data[nxt]
	msgStart := nxt + 1
	msgLen := int(s.Length1)
	if s.Length1 == 0xff {
		if len(data) < (msgStart + 2) {
			return offs, (msgStart + 2) - len(data), ErrIPFIXmoreBytes
		}
		s.Length2 = binary.BigEndian.Uint16(data[msgStart : msgStart+2])
		msgLen = int(s.Length2)
		msgStart += 2
	} else {
		s.Length2 = 0
	}
	if len(data) < (msgStart + msgLen) {
		return offs, msgStart + msgLen - len(data),
			ErrIPFIXmoreBytes
	}
	s.SipMsg = data[msgStart : msgStart+msgLen]
	return offs + msgStart + msgLen, 0, nil
}

// TODO: sctp
