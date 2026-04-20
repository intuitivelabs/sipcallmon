package sipcallmon

import (
	"encoding/binary"
	"errors"
)

const (
	IPFIXmsgHdrLen int = 16
	IPFIXsetHdrLen int = 4
)

const (
	IPFIXtemplateID        uint16 = 2
	IPFIXoptionsTemplateID uint16 = 3
)

var ErrIPFIXmoreBytes = errors.New("more  bytes needed")
var ErrIPFIXinvHdr = errors.New("invalid IPFIX header")
var ErrIPFIXinvLen = errors.New("invalid length in IPFIX field")
var ErrIPFIXbug = errors.New("bug while parsing or writing IPFIX message")

type IPFIXmsgHdr struct {
	Version     uint16 // 10 for the current version (rfc7011 && rfc5101)
	Length      uint16 // total length, including this header
	ExportTime  uint32 // export time in seconds
	SequenceNo  uint32 // msg. sequence number
	ObsDomainId uint32 // observation domain id
}

type IPFIXsetHdr struct {
	SetID  uint16 // 2 = Template Set, 3 Options Templates >= 256 - Data Set
	Length uint16 // length of the set including the set header & padding
}

// ParseIPFIXHdr parses an IPFIX header, from the message contained in buf
// and starting at offset offs.
// If the parsing requires more data (ErrIPFIXmoreBytes)
// this function should be called again with an extended buf containing the
// old data + new data and with offs equal to the last returned value.
// It returns: - a filled IPFIXmsgHdr
// - the offset immediately after the header
// - how much bigger the buffer needs to be if the header was bigger then the
// provided buf
// -a n error (nil on success, ErrIPFIXmoreBytes or ErrIPFIXInvHdr).
func ParseIPFIXmsgHdr(buf []byte, offs int) (IPFIXmsgHdr, int, int, error) {
	var hdr IPFIXmsgHdr

	msg := buf[offs:]
	if len(msg) < IPFIXmsgHdrLen {
		return hdr, offs, IPFIXmsgHdrLen - len(msg), ErrIPFIXmoreBytes
	}

	hdr.Version = binary.BigEndian.Uint16(msg[0:2])
	hdr.Length = binary.BigEndian.Uint16(msg[2:4])
	hdr.ExportTime = binary.BigEndian.Uint32(msg[4:8])
	hdr.SequenceNo = binary.BigEndian.Uint32(msg[8:12])
	hdr.ObsDomainId = binary.BigEndian.Uint32(msg[12:16])

	if int(hdr.Length) < IPFIXmsgHdrLen {
		// invalid message
		return hdr, offs, 0, ErrIPFIXinvHdr
	}
	return hdr, offs + IPFIXmsgHdrLen, 0, nil
}

// ParseIPFIXsetHdr parses an IPFIX set header, from buf, starting at offset
// offs.
// If the parsing requires more data (ErrIPFIXmoreBytes)
// this function should be called again with an extended buf containing the
// old data + new data and with offs equal to the last returned value.
// It returns: - a filled IPFIXmsgHdr
// - the offset immediately after the header
// - how much bigger the buffer needs to be if the header was bigger then the
// provided buf
// -a n error (nil on success, ErrIPFIXmoreBytes or ErrIPFIXInvHdr).
func ParseIPFIXsetHdr(buf []byte, offs int) (IPFIXsetHdr, int, int, error) {
	var shdr IPFIXsetHdr

	data := buf[offs:]
	if len(data) < IPFIXsetHdrLen {
		return shdr, offs, IPFIXsetHdrLen - len(data), ErrIPFIXmoreBytes
	}

	shdr.SetID = binary.BigEndian.Uint16(data[0:2])
	shdr.Length = binary.BigEndian.Uint16(data[2:4])

	if int(shdr.Length) < IPFIXsetHdrLen {
		// invalid message
		return shdr, offs, 0, ErrIPFIXinvHdr
	}
	return shdr, offs + IPFIXsetHdrLen, 0, nil
}

const IPFIXvarLenElemMinLen int = 1 // empty variable-length element size

// IPFIXvarLenElem is used to hold a parsed ipfix variable-length
// information element (e.g. byte array, string a.s.o.).
// See RFC5102 Section 7.
//
// If Length1 is less then 0xff, then the lenght is fully
// contained in Length1 and Length2 will be 0
// (the message on the wire is of the form Length1 | string[Lenght1]).
// If Length1 is 0xff, the the actual length is store in Lenght2
// (the message on the wire if of the form  0xff | Length2 | string [Lenght2])
type IPFIXvarLenElem struct {
	Length1 uint8  // first byte of length, 0xff if length in length2
	Length2 uint16 // 0 if length1 < 0xff (length is in Length1)
	V       []byte // points inside the parsed data
}

func (vle IPFIXvarLenElem) String() string {
	return string(vle.V)
}

// ParseIPFIXvarLenElem parses an IPFIX variable-length element from the message
// contained in buf and starting at offset offs.
// If the parsing requires more data (ErrIPFIXmoreBytes)
// this function should be called again with an extended buf containing the
// old data + new data and with offs equal to the last returned value.
// It returns: - a filled IPFIXvarLenElem, with V set to a byte slice pointing
// / inside the buffer passed as argument.
// - the offset immediately after the header
// - how much bigger the buffer needs to be if the header was bigger then the
// provided buf
// -a n error (nil on success or ErrIPFIXmoreBytes).
func ParseIPFIXvarLenElem(buf []byte, offs int) (IPFIXvarLenElem,
	int, int, error) {
	var vle IPFIXvarLenElem

	data := buf[offs:]
	if len(data) < IPFIXvarLenElemMinLen {
		return vle, offs, IPFIXvarLenElemMinLen - len(data), ErrIPFIXmoreBytes
	}
	vle.Length1 = data[0]
	start := 1
	vlen := int(vle.Length1)
	if vle.Length1 == 0xff {
		if len(data) < (start + 2) {
			return vle, offs, (start + 2) - len(data), ErrIPFIXmoreBytes
		}
		vle.Length2 = binary.BigEndian.Uint16(data[start : start+2])
		vlen = int(vle.Length2)
		start += 2
	} else {
		vle.Length2 = 0
	}
	if len(data) < (start + vlen) {
		return vle, offs, start + vlen - len(data), ErrIPFIXmoreBytes
	}
	vle.V = data[start : start+vlen]
	return vle, offs + start + vlen, 0, nil
}
