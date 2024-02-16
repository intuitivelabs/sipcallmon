package sipcallmon

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/intuitivelabs/calltr" // GetHash
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/unsafeconv"
)

// ethernet addresses used in generated pcaps (local)
var DefSrcEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0a}
var DefDstEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0b}

var errorPcapWQueueFull = errors.New("pcap dumper write queue full")
var errorPcapWNewMsgFailed = errors.New("pcap dumper message alloc failed")

var pcapSubDirChrSet = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

type PcapWriterCfg struct {
	NWorkers int    // number of worker threads started
	QueueLen int    // queue size per worker
	Dir      string // should contain the parent directory for the pcap files
	Prefix   string // should contain a file prefix (optional)
	Suffix   string // should contain file suffix + extension

	subDirs []string // array of subdirs for spreading the pcap files
}

// InitSubDirs will fill the subdirectory names used for spreading the
// created pcap files (relative to pcfg.Dir). flags specifies the method
// for creating the subdir names and no the number of the subdirectories
// (0 means disabled, all the files will be created directly in pcfg.Dir)
func (pcfg *PcapWriterCfg) InitSubDirs(flags int, no int) error {
	pcfg.subDirs = nil
	if no <= 0 {
		return nil
	}
	// find a good length for the subdirectories names
	chrSet := pcapSubDirChrSet
	chrSetLen := len(chrSet)
	l := 1
	for r := chrSetLen; r <= no; r, l = r*chrSetLen, l+1 {
	}
	pcfg.subDirs = make([]string, no)
	for i := 0; i < no; i++ {
		n := make([]byte, l+1)
		for k, v := 0, i; k < l; k, v = k+1, v/chrSetLen {
			n[l-1-k] = chrSet[v%chrSetLen]
		}
		n[l] = '/'
		pcfg.subDirs[i] = string(n)
		DBG("pcap dump config: subdir[%05d] = %q\n", i, pcfg.subDirs[i])
	}
	return nil
}

func (pcfg PcapWriterCfg) PcapFileName(key []byte) string {
	escKey := url.PathEscape(unsafeconv.Str(key))
	return pcfg.Prefix + escKey + pcfg.Suffix
}

// PcapFileRelPath returns the relative path to pcfg.Dir of the output
// pcap file  corresponding to "key". It includes the file name.
func (pcfg PcapWriterCfg) PcapFileRelPath(key []byte) string {
	return pcfg.PcapFileSubDir(key) + pcfg.PcapFileName(key)
}

func (pcfg PcapWriterCfg) PcapFileFullPath(key []byte) (fpath, dirpath string) {
	dirpath = pcfg.Dir + pcfg.PcapFileSubDir(key)
	fpath = dirpath + pcfg.PcapFileName(key)
	return
}

// PcapFileSubDir returns the corresponding subdirectory for writing
// the file specified by "key".
func (pcfg PcapWriterCfg) PcapFileSubDir(key []byte) string {
	if len(pcfg.subDirs) != 0 {
		h := calltr.GetHash2(key, 0, len(key))
		return pcfg.subDirs[h%uint32(len(pcfg.subDirs))]
	}
	return ""
}

// PcapWriter writes messages into pcap files.
type PcapWriter struct {
	cfg PcapWriterCfg

	wrWorkers []PcapWrWorker // internal workers
	running   int            // number of running workers
	init      bool
	stats     *pcapStatsT
}

func (pw *PcapWriter) Init(cfg PcapWriterCfg) bool {

	if err, gstats := pcapGlobalStatsInit(); err != nil || gstats == nil {
		ERR("failed to init pcap writer stats: %s\n", err)
		return false
	} else {
		pw.stats = gstats
	}
	pw.cfg = cfg
	pw.wrWorkers = make([]PcapWrWorker, pw.cfg.NWorkers)
	pw.init = true
	for i := 0; i < len(pw.wrWorkers); i++ {
		name := fmt.Sprintf("pcap_writer_%03d", i)
		if err := pw.wrWorkers[i].Init(name, &pw.cfg, pw.stats); err != nil {
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
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return fmt.Errorf("PcapWrite::WriteRawMsg: BUG: not initialized")
	}
	h := calltr.GetHash2(msg, int(key.Offs), int(key.Len))
	i := int(h) % pw.running
	m := NewPcapWrMsg(key, flags, msg)
	if m != nil {
		if !pw.wrWorkers[i].QueueMsg(m) {
			ERR("queue size exceeded for %q size %d worker %d\n",
				key.Get(msg), len(msg), i)
			FreePcapWrMsg(&m)
			return errorPcapWQueueFull
		}
	} else {
		pw.stats.cnts.Inc(pw.stats.hErrOther)
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
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return fmt.Errorf("PcapWriter::WriteUDPmsg:"+
			" payload or key too small (%d, %d)", len(payload), key.Len)
	}

	isIPv4 := sip.To4() != nil
	if isIPv4 != (dip.To4() != nil) {
		// error: mismatched address families
		pw.stats.cnts.Inc(pw.stats.hBUG)
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
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return err
	}
	k := key
	k.Offs += sipsp.OffsT(hlen) // adjust offset
	return pw.WriteRawMsg(k, flags, sbuf.Bytes())
}
