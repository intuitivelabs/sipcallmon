package sipcallmon

import (
	"errors"
	"fmt"
	"hash/maphash"
	"net"
	"strconv"
	"time"
	//"net/url"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	//"github.com/intuitivelabs/calltr" // GetHash
	"github.com/intuitivelabs/bytescase"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/unsafeconv"

	"github.com/zeebo/xxh3"
)

// ethernet addresses used in generated pcaps (local)
var DefSrcEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0a}
var DefDstEthAddr = net.HardwareAddr{0x02, 0x05, 0x01, 0x04, 0x0c, 0x0b}

var errorPcapWQueueFull = errors.New("pcap dumper write queue full")
var errorPcapWNewMsgFailed = errors.New("pcap dumper message alloc failed")

var pcapSubDirChrSet = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

type PcapIdHashT uint8

const (
	PcapIdHashNone PcapIdHashT = iota
	PcapIdHashMD5
	PcapIdHashSHA256
	PcapIdHashXXHash
	PcapIdHashXXHash128
	PcapIdHashBlake256
	PcapIdHashBlake384
	PcapIdHashInvalid // marker
)

var pcapIdHashNames = [...][]string{
	PcapIdHashNone:      {"none"},
	PcapIdHashMD5:       {"md5"},
	PcapIdHashSHA256:    {"sha256"},
	PcapIdHashXXHash:    {"xxhash64", "xxhash"},
	PcapIdHashXXHash128: {"xxhash128"},
	PcapIdHashBlake256:  {"blake3_256", "blake256", "blake3"},
	PcapIdHashBlake384:  {"blake3_384", "blake384"},
}

var errPcapWrCfgInvHash = errors.New("pcap dump config: invalid id hash type")

func (h PcapIdHashT) String() string {
	if int(h) < len(pcapIdHashNames) {
		return pcapIdHashNames[h][0]
	}
	return "invalid"
}

func ParsePcapIdHashT(s string) PcapIdHashT {
	val := unsafeconv.Bytes(s)
	for h, names := range pcapIdHashNames {
		for _, n := range names {
			if bytescase.CmpEq(unsafeconv.Bytes(n), val) {
				return PcapIdHashT(h)
			}
		}
	}
	return PcapIdHashInvalid
}

type PcapWriterCfg struct {
	NWorkers int         // number of worker threads started
	QueueLen int         // queue size per worker
	Dir      string      // should contain the parent directory for the pcap files
	Prefix   string      // should contain a file prefix (optional)
	Suffix   string      // should contain file suffix + extension
	Upload   string      // upload URL
	RestCfg  RESTcfg     // config for pcap uploader over http
	IdHash   PcapIdHashT // hash used when generating the upload id

	FdBuckets      int           // hash buckets for fd tracker (0 = disabled)
	FdPrealloc     int           // pre-allocated fd tracker entries per worker
	FdMaxOpen      int           // max tracked open fds globally (0 = unlimited)
	RotateInterval time.Duration // pcap file rotation interval
	RotateSuffix   string        // rename extension on rotation (e.g. ".pcap")
	RotateDir      string        // move rotated files to this directory
	RotateFmt      string        // format string for rotated filenames

	// file uploader config
	FileUpldWorkers  int    // number of file upload workers (0 = disabled)
	FileUpldQueueLen int    // upload channel + pool size
	FileUpldDoneDir  string // post-upload success: "" = delete, "leave", or dir path
	FileUpldErrDir   string // post-upload error: "" = leave, "delete", or dir path
	FileUpldNotify   string // "channel", "watch", "both"
	FileUpldStartupScan bool // scan RotateDir on startup for leftovers

	rotateFmtSegs     []pcapRotFmtSeg // compiled format (parsed once in Init)
	rotateFmtHasRetry bool            // true if format contains %R, %N, or %U

	init    bool
	wSeed   maphash.Seed // seed for workers dist.: init to random hash seed
	subDirs []string     // array of subdirs for spreading the pcap files
}

func (pcfg *PcapWriterCfg) Init() {
	pcfg.wSeed = maphash.MakeSeed()
	if pcfg.RestCfg.Method == "" {
		pcfg.RestCfg.Method = "POST"
	}
	if pcfg.RestCfg.ContentType == "" {
		pcfg.RestCfg.ContentType = "application/octet-stream"
	}
	pcfg.rotateFmtSegs, pcfg.rotateFmtHasRetry = parseRotateFmt(pcfg.RotateFmt)
	if len(pcfg.rotateFmtSegs) == 0 {
		pcfg.rotateFmtSegs, pcfg.rotateFmtHasRetry = parseRotateFmt("%b_%s%e")
	}

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

// PcapMaxFileNameLen will return the maximum lenght for the
// filename produced by PcapFileName.
func (pcfg PcapWriterCfg) PcapMaxFileNameLen(key []byte) int {
	return len(pcfg.Prefix) + 3*len(key) + len(pcfg.Suffix)
}

// PcapMinFileNameLen will return the minimum lenght for the
// filename produced by PcapFileName.
func (pcfg PcapWriterCfg) PcapMinFileNameLen(key []byte) int {
	return len(pcfg.Prefix) + len(key) + len(pcfg.Suffix)
}

// PcapFileName will create a filename based on the provided key.
// The result is written in dst (which has to provide enough space).
// It returns the number of bytes written and an error.
func (pcfg PcapWriterCfg) PcapFileName(dst, key []byte) (int, error) {
	if pcfg.PcapMinFileNameLen(key) > len(dst) {
		return 0, errFileEscDstTooSmall
	}
	flen, err := FileEscapeSafe(dst[len(pcfg.Prefix):], key)
	if err != nil {
		return 0, err
	}
	copy(dst[0:], pcfg.Prefix)
	copy(dst[len(pcfg.Prefix)+flen:], pcfg.Suffix)
	return len(pcfg.Prefix) + flen + len(pcfg.Suffix), nil
}

// Returns the number of bytes written into dst or an error if
// dst was too small or the hash id was wrong.
func (pcfg PcapWriterCfg) PcapUploadId(dst []byte, key []byte) (int, error) {

	switch pcfg.IdHash {
	case PcapIdHashNone:
		if len(key) > len(dst) {
			return 0, errUrlEncDstTooSmall
		}
		return UploadIdEscape(dst, key)
		//return URLEscape(dst, key)
		/*
			k := url.QueryEscape(unsafeconv.Str(key))
			n := copy(dst, k)
			if len(k) > len(dst) {
				return n, errUrlEncDstTooSmall
			}
			return n, nil
		*/
	case PcapIdHashMD5:
		return MD5URLSafe(dst, key)
	case PcapIdHashSHA256:
		return SHA256URLSafe(dst, key)
	case PcapIdHashXXHash:
		return XXHashURLSafe(dst, key)
	case PcapIdHashXXHash128:
		return XXHash128URLSafe(dst, key)
	case PcapIdHashBlake256:
		return Blake3URLSafe256(dst, key)
	case PcapIdHashBlake384:
		return Blake3URLSafe384(dst, key)
	}
	return 0, errPcapWrCfgInvHash
}

// PcapRotatedName builds the expected rotated filename for the given key
// and timestamp. Non-deterministic specifiers (%r, %n, %R, %N, %U) are
// replaced with '*'. This produces a glob pattern usable for finding
// the actual file. Deterministic specifiers (%b, %e, %f, %d, %s, %ms,
// %ns, %t{}, %i, %%) are resolved normally.
// The result is written into dst. Returns the number of bytes written.
func (pcfg PcapWriterCfg) PcapRotatedName(dst, key []byte,
	ts time.Time) (int, error) {

	// build oldName via PcapFileFullPath
	var fPathBuf [256]byte
	fPathLen, _, err := pcfg.PcapFileFullPath(fPathBuf[:], key)
	if err != nil {
		return 0, err
	}
	oldName := fPathBuf[:fPathLen]
	baseName, ext := splitOldName(oldName)

	buf := dst[:0]
	segs := pcfg.rotateFmtSegs

	for i := range segs {
		seg := &segs[i]
		switch seg.op {
		case rotFmtLiteral:
			buf = append(buf, seg.lit...)
		case rotFmtBase:
			buf = append(buf, baseName...)
		case rotFmtExt:
			if len(pcfg.RotateSuffix) > 0 {
				if pcfg.RotateSuffix[0] != '.' &&
					(len(buf) > 0 && buf[len(buf)-1] != '.') {
					buf = append(buf, '.')
				}
				buf = append(buf, pcfg.RotateSuffix...)
			} else {
				if len(buf) > 0 && buf[len(buf)-1] == '.' && len(ext) > 0 {
					buf = append(buf, ext[1:]...)
				} else {
					buf = append(buf, ext...)
				}
			}
		case rotFmtFull:
			buf = append(buf, baseName...)
			buf = append(buf, ext...)
		case rotFmtTsSec:
			buf = strconv.AppendInt(buf, ts.Unix(), 10)
		case rotFmtTsMs:
			buf = strconv.AppendInt(buf, ts.UnixMilli(), 10)
		case rotFmtTsNs:
			buf = strconv.AppendInt(buf, ts.UnixNano(), 10)
		case rotFmtTimeLayout:
			buf = ts.AppendFormat(buf, seg.lit)
		case rotFmtUploadId:
			avail := cap(buf) - len(buf)
			if avail < 128 {
				break
			}
			n, err := pcfg.PcapUploadId(buf[len(buf):cap(buf)], key)
			if err == nil {
				buf = buf[:len(buf)+n]
			}
		case rotFmtRand, rotFmtSeq:
			// non-deterministic: emit glob wildcard
			buf = append(buf, '*')
		case rotFmtConflictRand, rotFmtConflictSeq, rotFmtConflictRetry:
			// conflict-only: emit nothing (same as retry=0)
		}
	}
	n := len(buf)
	if n > len(dst) {
		return 0, errPathEscDstTooSmall
	}
	return n, nil
}

// PcapFileRelPath returns the relative path to pcfg.Dir of the output
// pcap file  corresponding to "key". It includes the file name.
func (pcfg PcapWriterCfg) PcapFileRelPath(dst, key []byte) (int, error) {

	subdir := pcfg.PcapFileSubDir(key)
	if len(subdir)+pcfg.PcapMinFileNameLen(key) > len(dst) {
		return 0, errPathEscDstTooSmall
	}
	flen, err := pcfg.PcapFileName(dst[len(subdir):], key)
	if err != nil {
		return 0, err
	}
	copy(dst[0:], subdir)
	return len(subdir) + flen, nil
}

// PcapMaxDirPathLen will return the maximum length for the
// directory path produced by PcapFileFullPath
func (pcfg PcapWriterCfg) PcapMaxDirPathLen(key []byte) int {
	subdir := pcfg.PcapFileSubDir(key)
	return len(pcfg.Dir) + len(subdir)
}

// PcapMaxFullPathLen will return the maximum length for the
// the full file path (including directories and filename)
// produced by PcapFileFullPath
func (pcfg PcapWriterCfg) PcapMaxFullPathLen(key []byte) int {
	return pcfg.PcapMaxDirPathLen(key) + pcfg.PcapMaxFileNameLen(key)
}

// PcapFileFullPath will fill fpath with the full pcap file path
// (including directories) for the given key.
// The result is written into fpath  (which has to provide enough space).
// It returns the number of bytes written in fpath, the  length of the directory path
// and an error.
// fpath[:flen] will contain the full file path, complete with directories
// fpath[:dlen] will contain only the directories
// fpath[dlen:] will contain only the filename
func (pcfg PcapWriterCfg) PcapFileFullPath(fpath, key []byte) (flen, dlen int,
	err error) {
	subdir := pcfg.PcapFileSubDir(key)
	if len(pcfg.Dir)+len(subdir)+pcfg.PcapMinFileNameLen(key) > len(fpath) {
		return 0, 0, errFileEscDstTooSmall
	}
	dlen = copy(fpath, pcfg.Dir)
	dlen += copy(fpath[dlen:], subdir)
	flen, err = pcfg.PcapFileName(fpath[dlen:], key)
	if err == nil {
		flen += dlen
	}
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

	wrWorkers []PcapWrWorker      // internal workers
	uploader  *pcapFileUploader   // file upload worker pool (nil if disabled)
	running   int                 // number of running workers
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
	wrFlags := PcapWrWorkerEmptyF
	if len(cfg.Upload) != 0 {
		wrFlags |= PcapWrWorkerUploadF
	} else {
		// no upload configured => to file
		wrFlags |= PcapWrWorkerFileF
	}
	if len(cfg.Dir) != 0 {
		// if dir configured force write also to file
		wrFlags |= PcapWrWorkerFileF
	}
	// init file upload workers if configured
	if pw.cfg.FileUpldWorkers > 0 && len(pw.cfg.Upload) > 0 {
		pw.uploader = &pcapFileUploader{}
		if err := pw.uploader.Init(&pw.cfg, pw.stats); err != nil {
			ERR("pcap file uploader init failed: %v\n", err)
			pw.uploader = nil
		}
	}

	for i := 0; i < len(pw.wrWorkers); i++ {
		name := fmt.Sprintf("pcap_writer_%03d", i)
		if err := pw.wrWorkers[i].Init(name, wrFlags, &pw.cfg, pw.stats); err != nil {
			pw.wrWorkers = pw.wrWorkers[0:i]
			return false // some init error
		}
		// set upload channel on worker if channel mode is active
		if pw.uploader != nil {
			pw.wrWorkers[i].upldCh = pw.uploader.UpldCh()
			pw.wrWorkers[i].upldPool = pw.uploader.Pool()
		}
		// TODO: if both PcapWrWorkerUploadF and PcapWrWorkerFileF are set start
		//       separate workers and send a copy of the packet to both of them
	}
	return true
}

func (pw *PcapWriter) Start() bool {
	// start uploader first so channel is ready before workers send
	if pw.uploader != nil {
		pw.uploader.Start()
	}
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
	// stop workers first (they may still send to uploadCh)
	for i := 0; i < pw.running; i++ {
		pw.wrWorkers[i].Stop()
	}
	// then stop uploader (drains remaining upload requests)
	if pw.uploader != nil {
		pw.uploader.Stop()
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
	ts timestamp.TS, flags PcapWrMsgFlags, msg []byte) error {
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
	m := NewPcapWrMsg(key, keyBuf, ts, flags, msg)
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
	ts timestamp.TS, flags PcapWrMsgFlags, payload []byte) error {

	var err error
	var keySrc []byte

	if keyBuf != nil {
		keySrc = keyBuf
	} else {
		keySrc = payload
	}

	if key.Len < 4 || len(keySrc) < int(uint(key.Offs+key.Len)) {
		if len(keySrc) < int(uint(key.Offs+key.Len)) {
			BUG("PcapWriter::WriteUDPmsg: key outside payload: (%d, %d) len(p) = %d\n",
				key.Offs, key.Len, len(payload))
			pw.stats.cnts.Inc(pw.stats.hBUG)
			return fmt.Errorf("BUG: PcapWriter::WriteUDPmsg:"+
				" key (%d, %d) outside keybuf/payload (%d, %d, %d)",
				key.Offs, key.Len, len(payload), len(keySrc), key.Len)
		}
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
	return pw.WriteRawMsg(k, keyBuf, ts, flags, sbuf.Bytes())
}

// EndCall signals end-of-call for the given key.
// Queues a control message with PcapDumpCloseFileF and empty payload.
// The worker will close and rotate the tracked pcap file (if any).
// keyBuf must not be nil.
func (pw *PcapWriter) EndCall(key sipsp.PField, keyBuf []byte) error {
	return pw.WriteRawMsg(key, keyBuf, 0, PcapDumpCloseFileF, nil)
}
