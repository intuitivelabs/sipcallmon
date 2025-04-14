package sipcallmon

import (
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"net/url"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	//"github.com/intuitivelabs/calltr" // GetHash
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/unsafeconv"
	"github.com/zeebo/xxh3"
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

	init    bool
	wSeed   maphash.Seed // seed for workers dist.: init to random hash seed
	subDirs []string     // array of subdirs for spreading the pcap files
}

func (pcfg *PcapWriterCfg) Init() {
	pcfg.wSeed = maphash.MakeSeed()

	pcfg.init = true
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
		// DBG("pcap dump config: subdir[%05d] = %q\n", i, pcfg.subDirs[i])
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
		h := pcfg.Hash(key)
		return pcfg.subDirs[h%uint64(len(pcfg.subDirs))]
	}
	return ""
}

// Hash function used for mapping call-ids (keys) to directories
func (pcfg PcapWriterCfg) Hash(key []byte) uint64 {
	/* maphash is the fastest, but it always uses a random seed
	   vector initialised at start-up (even if called with the same seed)
	   so it cannot be used if the pcap files subdir. distribution needs
	   to be consistent across runs (same call-id ends in the same subdir)
	   xxh3 is the second best option in terms of speed.
	   GetHash is faster then GetHash2 and for call-ids the distribution
	   is similar. It's about 2.5x slower then the native maphash version
	   (that uses amd64 aes instructions).
	*/
	//return uint64(calltr.GetHash2(key, 0, len(key)))
	//return maphash.Bytes(dirSeed, key)
	return xxh3.Hash(key)
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
	if !pw.cfg.init {
		pw.cfg.Init()
	}
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

func (pw *PcapWriter) WorkersNo() int {
	return pw.running
}

// MinMsgWorkers returns the minimum number of messages processed by a worker.
func (pw *PcapWriter) MinMsgWorker() uint64 {
	if pw.running < 1 {
		return 0
	}
	min := pw.wrWorkers[0].TotalMsgs()
	for i := 1; i < pw.running; i++ {
		no := pw.wrWorkers[i].TotalMsgs()
		if no < min {
			min = no
		}
	}
	return min
}

// key points inside keyBuf or inside msg (if keyBuf == nil)
func (pw *PcapWriter) WriteRawMsg(key sipsp.PField, keyBuf []byte,
	flags PcapWrMsgFlags, msg []byte) error {
	var keyVal []byte

	if pw.running < 1 {
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return fmt.Errorf("PcapWrite::WriteRawMsg: BUG: not initialized")
	}
	if keyBuf != nil {
		keyVal = key.Get(keyBuf)
	} else {
		keyVal = key.Get(msg)
	}
	h := maphash.Bytes(pw.cfg.wSeed, keyVal)
	//h := calltr.GetHash2(keyVal, int(key.Offs), int(key.Len))
	i := uint64(h) % uint64(pw.running)
	m := NewPcapWrMsg(key, keyBuf, flags, msg)
	// DBG("msg key: %q h: %d i: %d (running %d)\n", keyVal, h, i, pw.running)
	// DBG("worker queued0: %d : %q h: %d\n", i, pw.wrWorkers[i].name, h)
	if m != nil {
		if !pw.wrWorkers[i].QueueMsg(m) {
			ERR("queue size exceeded for %q size %d worker %d\n",
				keyVal, len(msg), i)
			FreePcapWrMsg(m)
			return errorPcapWQueueFull
		}
		// DBG("worker queued: %d : %q h: %d\n", i, pw.wrWorkers[i].name, h)
	} else {
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return fmt.Errorf("PcapWrite::WriteRawMsg new msg failed for key %s",
			keyVal)
		return errorPcapWNewMsgFailed
	}
	return nil
}

// WriteUDPmsg takes the payload adds and UDP, IP and eth. header
// and then it queues the message for writing.
// key points inside keyBuf or inside payload (if keyBuf == nil)
func (pw *PcapWriter) WriteUDPmsg(sip net.IP, sport int,
	dip net.IP, dport int,
	key sipsp.PField, keyBuf []byte,
	flags PcapWrMsgFlags, payload []byte) error {

	var err error
	var keySrc []byte

	if keyBuf != nil {
		keySrc = keyBuf
	} else {
		keySrc = payload
	}

	if key.Len < 8 || len(keySrc) < int(uint(key.Len)) {
		// key or payload too small
		pw.stats.cnts.Inc(pw.stats.hErrOther)
		return fmt.Errorf("PcapWriter::WriteUDPmsg:"+
			" payload or key too small (%d, %d, %d)",
			len(payload), len(keySrc), key.Len)
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
	//sbuf := gopacket.NewSerializeBuffer()
	// we expect only prepend, hlen is max 62 , payload max
	// alternative: create a pool of SerializeBuffer of max size
	// (65535) and use it.
	sbuf := gopacket.NewSerializeBufferExpectedSize(hlen+len(payload), 0)
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
	if keyBuf == nil {
		// adjust key offset, but only if it points inside the payload
		k.Offs += sipsp.OffsT(hlen)
	}
	return pw.WriteRawMsg(k, keyBuf, flags, sbuf.Bytes())
}
