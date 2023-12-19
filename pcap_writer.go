package sipcallmon

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/intuitivelabs/calltr" // GetHash
	"github.com/intuitivelabs/sipsp"
)

// ethernet addresses used in generated pcaps (local)
var DefSrcEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0a}
var DefDstEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0b}

var errorPcapWQueueFull = errors.New("pcap dumper write queue full")
var errorPcapWNewMsgFailed = errors.New("pcap dumper message alloc failed")

type PcapWriterCfg struct {
	NWorkers int    // number of worker threads started
	QueueLen int    // queue size per worker
	Prefix   string // should contain directory + file prefix
	Suffix   string // should contain file suffix + extension
}

// PcapWriter writes messages into pcap files.
type PcapWriter struct {
	cfg PcapWriterCfg

	wrWorkers []PcapWrWorker // internal workers
	running   int            // number of running workers
	init      bool
}

func (pw *PcapWriter) Init(cfg PcapWriterCfg) bool {

	pw.cfg = cfg
	pw.wrWorkers = make([]PcapWrWorker, pw.cfg.NWorkers)
	pw.init = true
	for i := 0; i < len(pw.wrWorkers); i++ {
		name := fmt.Sprintf("pcap_writer_%03d", i)
		if err := pw.wrWorkers[i].Init(name, &pw.cfg); err != nil {
			pw.wrWorkers = pw.wrWorkers[0:i]
			return false // some init error
		}
	}
	return true
}

func (pw *PcapWriter) Start() bool {
	for i := 0; i < len(pw.wrWorkers); i++ {
		if !pw.wrWorkers[i].Start() {
			pw.running = i
			return false // error
		}
	}
	pw.running = len(pw.wrWorkers)
	return true
}

// Stop will signal all the processing go routines to stop and exit.
func (pw *PcapWriter) Stop() bool {
	DBG("PcapWriter Stop() called: %d workers\n", pw.running)
	for i := 0; i < pw.running; i++ {
		pw.wrWorkers[i].Stop()
	}
	return true
}

func (pw *PcapWriter) WriteRawMsg(key sipsp.PField, flags PcapWrMsgFlags,
	msg []byte) error {

	if pw.running < 1 {
		return fmt.Errorf("PcapWrite::WriteRawMsg: BUG: not initialized")
	}
	h := calltr.GetHash(msg, int(key.Offs), int(key.Len))
	i := int(h) % pw.running
	m := NewPcapWrMsg(key, flags, msg)
	if m != nil {
		if !pw.wrWorkers[i].QueueMsg(m) {
			ERR("queue size exceeded for %q size %d\n",
				key.Get(msg), len(msg))
			return errorPcapWQueueFull
		}
	} else {
		return fmt.Errorf("PcapWrite::WriteRawMsg new msg failed for key %s",
			key.Get(msg))
		return errorPcapWNewMsgFailed
	}
	return nil
}

// WriteUDPmsg takes the payload adds and UDP, IP and eth. header
// and then it queues the message for writing.
// key points inside the payload.
func (pw *PcapWriter) WriteUDPmsg(sip net.IP, sport int,
	dip net.IP, dport int,
	key sipsp.PField, flags PcapWrMsgFlags, payload []byte) error {

	var err error

	if key.Len < 8 || len(payload) < int(uint(key.Len)) {
		// key or payload too small
		return fmt.Errorf("PcapWriter::WriteUDPmsg:"+
			" payload or key too small (%d, %d)", len(payload), key.Len)
	}

	isIPv4 := sip.To4() != nil
	if isIPv4 != (dip.To4() != nil) {
		// error: mismatched address families
		return fmt.Errorf("PcapWriter:WriteUDPmsg: mismatched AF for %s %s",
			sip, dip)
	}
	ethType := layers.EthernetTypeIPv4
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var hlen int // added header length

	udp := layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(dport),
	}
	hlen += 8
	if isIPv4 {
		ipv4 = layers.IPv4{
			Version:  4,
			TTL:      16,
			SrcIP:    sip,
			DstIP:    dip,
			Protocol: layers.IPProtocolUDP,
		}
		udp.SetNetworkLayerForChecksum(&ipv4)
		hlen += 20
	} else {
		// IPv6
		ethType = layers.EthernetTypeIPv6
		ipv6 = layers.IPv6{
			Version:    6,
			HopLimit:   16,
			SrcIP:      sip,
			DstIP:      dip,
			NextHeader: layers.IPProtocolUDP,
		}
		udp.SetNetworkLayerForChecksum(&ipv6)
		hlen += 40
	}
	eth := layers.Ethernet{
		SrcMAC:       DefSrcEthAddr,
		DstMAC:       DefDstEthAddr,
		EthernetType: ethType,
		Length:       0, // not used for most ethtypes (srcmac|dstmac|type)
	}
	hlen += 14

	// build packet
	// TODO: use a fixed per PcapWriter gopacket serialize buffer
	sbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if isIPv4 {
		err = gopacket.SerializeLayers(sbuf, opts, &eth, &ipv4, &udp,
			gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(sbuf, opts, &eth, &ipv6, &udp,
			gopacket.Payload(payload))
	}
	if err != nil {
		return err
	}
	k := key
	k.Offs += sipsp.OffsT(hlen) // adjust offset
	return pw.WriteRawMsg(k, flags, sbuf.Bytes())
}
