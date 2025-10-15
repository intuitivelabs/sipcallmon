package sipcallmon

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/intuitivelabs/bytespool"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/unsafeconv"
)

type PcapWrMsgFlags uint32

const (
	PcapDumpAppendDefF   PcapWrMsgFlags = 0
	PcapDumpAppendOnlyF  PcapWrMsgFlags = 1
	PcapDumpNewFileF     PcapWrMsgFlags = 2        // new callid -> new file
	PcapMsgHdrKeyFieldF  PcapWrMsgFlags = 0x010000 // key in header and not in msg
	PcapMsgHdrKeyPaddedF PcapWrMsgFlags = 0x020000 // if set key size will be padded to 4b
	PcapMsgHdrTimestampF PcapWrMsgFlags = 0x040000 // header contains a 64 bit timestamp
)

var pcapWrMsgPool bytespool.Bpool


// PcapWrMsg contains the message that will be sent to the writer goroutine.
// It encapsulates the message key, some flags and the original message.
// internal format:
//
//		key - sipsp.PField (offs & len for the key)
//		flags - uint32  (PcapMsgHdrKeyFieldF  set if key is in header and not in msg)
//	     [ 8 byte timestamp if PcapMsgHdrTimestampF is set ]
//	     [ key space if key is not contained in msg and PcapMsgHdrKeyFieldF is set ]
//		msg - bytes array
//
// If the key is added to the header (PcapMsgHdrKeyFieldF set) and PcapMsgHdrKeyPaddedF
// is also set, then the key will be padded so that the next filed starts at a multiple
// of 4 bytes.
type PcapWrMsg []byte

func init() {
	// init the pcap write msg pool with a minimum size of 0,
	// a maximum size of 64kb and allocations in multiples of
	// 512 bytes.
	if !pcapWrMsgPool.Init(0, 65536, 512) {
		Log.PANIC("pcap write msg pool init failed\n")
	}
}

// NewPcapWrMsg builds a new message for pcap writer. If KeyBuf is nil
//
//	the Key will be assumed to point inside msg and the key will not be
//	added to the PcapWrMsg header.
//	If PcapMsgHdrTimestampF is set the timestamp (ts) will be added to the message
//	header (otherwise it will be ignored).
func NewPcapWrMsg(Key sipsp.PField, KeyBuf []byte, ts timestamp.TS, flags PcapWrMsgFlags,
	msg []byte) PcapWrMsg {

	offsFlags := int(unsafe.Sizeof(Key))
	offs := int(unsafe.Sizeof(Key) + unsafe.Sizeof(flags))
	offsTimestamp := -1
	if flags&PcapMsgHdrTimestampF != 0 {
		offsTimestamp = offs
		offs += int(unsafe.Sizeof(ts))
	}
	// offset to start of message or key
	offsKeyVal := offs
	if KeyBuf != nil {
		// separate key (not contained in msg)
		flags |= PcapMsgHdrKeyFieldF
	} else {
		KeyBuf = msg // key inside msg
	}
	if flags&PcapMsgHdrKeyFieldF != 0 { // key value is stored in header
		offs += int(Key.Len)
		if flags&PcapMsgHdrKeyPaddedF != 0 {
			// pad to 4 bytes
			offs = padOffs(offs)
		}
	} else { // the key value is stored inside the msg part
		offsKeyVal = -1 // not used, not in header
	}

	sz := offs + len(msg)
	if Key.Len == 0 || (int(uint(Key.Offs)+uint(Key.Len)) > len(KeyBuf)) {
		// invalid key or msg
		return nil
	}
	//  "github.com/intuitivelabs/bytespool"
	// (uses multiple pools for different block sizes)
	buf, hit := pcapWrMsgPool.Get(sz, true)

	pkey := (*sipsp.PField)(unsafe.Pointer(&buf[0]))
	*pkey = Key
	//pflags := (*PcapWrMsgFlags)(unsafe.Pointer(&buf[offsFlags]))
	//*pflags = flags
	binary.NativeEndian.PutUint32(buf[offsFlags:], uint32(flags))

	if flags&PcapMsgHdrTimestampF != 0 {
		// pTimestamp := (*timestamp.TS)(unsafe.Pointer(&buf[offsTimestamp]))
		// *pTimestamp = ts
		binary.NativeEndian.PutUint64(buf[offsTimestamp:], uint64(ts))
	}

	if flags&PcapMsgHdrKeyFieldF != 0 {
		copy(buf[offsKeyVal:], Key.Get(KeyBuf))
		(*pkey).Offs = 0 // starts at begining (copied only the key)
	} // else key val is in the message

	copy(buf[offs:], msg)
	pcapStats.cnts.Inc(pcapStats.hAllocMsgs)
	pcapStats.cnts.Add(pcapStats.hAllocBytes, counters.Val(sz))
	if hit {
		pcapStats.cnts.Inc(pcapStats.hAllocHits)
	}
	return PcapWrMsg(buf)
}

func FreePcapWrMsg(pwm PcapWrMsg) {
	sz := len(pwm)
	// put back into pool (free)
	pcapWrMsgPool.Put(pwm)
	pcapStats.cnts.Dec(pcapStats.hAllocMsgs)
	pcapStats.cnts.Sub(pcapStats.hAllocBytes, counters.Val(sz))
}

// Format:
//     key offs (2 bytes), key len (2 bytes),
//     flags (4 bytes)
//     [ optional 8 byte timestamp if PcapMsgHdrTimestampF is set ]
//     [optional key value if iPcapMsgHdrKeyFieldF  is set, padded if PcapMsgHdrKeyPaddedF]
//     message ...
//Key     sipsp.PField
//Content []byte

func (pwm PcapWrMsg) RawKey() []byte {
	var k sipsp.PField
	var f PcapWrMsgFlags
	var ts timestamp.TS

	offsFlags := int(unsafe.Sizeof(k))
	offs := offsFlags + int(unsafe.Sizeof(f))
	if len(pwm) < offs {
		// too small
		return nil
	}
	// f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offsFlags]))
	f = PcapWrMsgFlags(binary.NativeEndian.Uint32(pwm[offsFlags:]))
	if f&PcapMsgHdrTimestampF != 0 {
		// header contains optional timestamp
		offs += int(unsafe.Sizeof(ts))
	}
	// keyBuf starts after the flags or timestamp in both cases:
	// 1. key val is stored in the optional field after the header
	//    (in this case k.Offs = 0)
	// 2. key val is inside the message (k.Offs will point to right place)
	offsKeyBuf := offs
	if len(pwm) < offsKeyBuf {
		// too small
		return nil
	}
	if len(pwm) < (int(k.Offs) + int(k.Len) + offsKeyBuf) {
		// too small
		return nil
	}
	k = *(*sipsp.PField)(unsafe.Pointer(&pwm[0]))
	return k.Get(pwm[offsKeyBuf:])
}

func (pwm PcapWrMsg) RawMsg() []byte {
	var k sipsp.PField
	var f PcapWrMsgFlags
	var ts timestamp.TS

	offsFlags := int(unsafe.Sizeof(k))
	offs := int(unsafe.Sizeof(k) + unsafe.Sizeof(f))
	if len(pwm) < offs {
		// too small
		return nil
	}
	k = *(*sipsp.PField)(unsafe.Pointer(&pwm[0]))
	/// f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offsFlags]))
	f = PcapWrMsgFlags(binary.NativeEndian.Uint32(pwm[offsFlags:]))
	if f&PcapMsgHdrTimestampF != 0 {
		// header contains optional timestamp
		offs += int(unsafe.Sizeof(ts))
	}
	if f&PcapMsgHdrKeyFieldF != 0 {
		// key is stored in the "header" and does not point
		// inside the msg
		// (in this case k.Offset should always be 0)
		offs += int(k.Offs) + int(k.Len)
		if f&PcapMsgHdrKeyPaddedF != 0 {
			offs = padOffs(offs)
		}
		if len(pwm) < offs {
			// too small
			return nil
		}
	}
	b := pwm[offs:]
	return b
}

func (pwm PcapWrMsg) Flags() PcapWrMsgFlags {
	var k sipsp.PField
	var f PcapWrMsgFlags

	offsFlags := int(unsafe.Sizeof(k))
	if len(pwm) < (offsFlags + int(unsafe.Sizeof(f))) {
		// too small
		return 0
	}
	// f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offs]))
	f = PcapWrMsgFlags(binary.NativeEndian.Uint32(pwm[offsFlags:]))
	return f
}

func (pwm PcapWrMsg) TS() timestamp.TS {
	var k sipsp.PField
	var f PcapWrMsgFlags
	var ts timestamp.TS

	offsFlags := int(unsafe.Sizeof(k))
	offsTimestamp := offsFlags + int(unsafe.Sizeof(f))
	if len(pwm) < (offsTimestamp + int(unsafe.Sizeof(ts))) {
		// too small
		return ts
	}
	// f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offs]))
	f = PcapWrMsgFlags(binary.NativeEndian.Uint32(pwm[offsFlags:]))
	if f&PcapMsgHdrTimestampF != 0 {
		// header contains optional timestamp
		ts = timestamp.TS(binary.NativeEndian.Uint64(pwm[offsTimestamp:]))
	}
	return ts
}

func (pwm PcapWrMsg) Parse() (key []byte, flags PcapWrMsgFlags, ts timestamp.TS, msg []byte) {
	var k sipsp.PField

	offsFlags := int(unsafe.Sizeof(k))
	offs := int(unsafe.Sizeof(k) + unsafe.Sizeof(flags))
	if len(pwm) < offs {
		// too small
		return // key == nil (error) ...
	}
	k = *(*sipsp.PField)(unsafe.Pointer(&pwm[0]))
	/// f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offsFlags]))
	flags = PcapWrMsgFlags(binary.NativeEndian.Uint32(pwm[offsFlags:]))
	offsTimestamp := -1
	if flags&PcapMsgHdrTimestampF != 0 {
		// header contains optional timestamp
		offsTimestamp = offs
		offs += int(unsafe.Sizeof(ts))
	}
	// in both cases: key in header or in message the key "buffer" starts
	// after the optional timestamp
	offsKeyBuf := offs
	if flags&PcapMsgHdrKeyFieldF != 0 {
		// key is stored in the "header" and does not point
		// inside the msg
		// (in this case k.Offset should always be 0)
		offs += int(k.Offs) + int(k.Len)
		if flags&PcapMsgHdrKeyPaddedF != 0 {
			offs = padOffs(offs)
		}
	}
	if len(pwm) < (int(k.Offs) + int(k.Len) + offsKeyBuf) {
		// too small
		return // key == nil (error) ...
	}
	key = k.Get(pwm[offsKeyBuf:])
	if flags&PcapMsgHdrTimestampF != 0 {
		ts = timestamp.TS(binary.NativeEndian.Uint64(pwm[offsTimestamp:]))
	}
	msg = pwm[offs:]
	return
}

// return the padded value
func padOffs(offs int) int {
	return (offs + 3) & (^3)
}

var ErrBadPcapIntMsg = errors.New("bug: bad internal pcap wr message")

type PcapWrWorker struct {
	msgs chan PcapWrMsg

	init    bool // true after Init()
	running bool // true after Start()
	name    string
	cfg     *PcapWriterCfg

	stop     chan struct{} // internal strop (via Strop())
	wg       sync.WaitGroup
	initLock sync.Mutex // avoid running Stop() in parallel
	stats    *pcapStatsT
	tmsgs    atomic.Uint64 // total messages handled
}

func (pwr *PcapWrWorker) Init(name string, cfg *PcapWriterCfg,
	stats *pcapStatsT) error {
	pwr.initLock.Lock()
	pwr.name = name
	pwr.msgs = make(chan PcapWrMsg, cfg.QueueLen)
	pwr.stop = make(chan struct{}, 1)
	pwr.init = true
	pwr.cfg = cfg
	pwr.stats = stats
	pwr.initLock.Unlock()
	return nil
}

func (pwr *PcapWrWorker) Start() bool {
	if !pwr.init {
		return false
	}
	go func() {
		pwr.wg.Add(1)
		pwr.run()
		pwr.wg.Done()
	}()
	return true
}

func (pwr *PcapWrWorker) Stop() bool {
	pwr.initLock.Lock()
	if pwr.init {
		close(pwr.stop)
		pwr.wg.Wait()
		pwr.stop = nil
		pwr.init = false
	}
	pwr.initLock.Unlock()
	return true
}

func (pwr *PcapWrWorker) QueueMsg(m PcapWrMsg) bool {
	if !pwr.init || pwr.msgs == nil {
		return false
	}
	pwr.stats.cnts.Inc(pwr.stats.hQueuedMsgs) // before send
	select {
	case pwr.msgs <- m:
		pwr.stats.cnts.Inc(pwr.stats.hTQueuedMsgs)

		//DBG("message queued to %q\n", pwr.name)
		break
	default:
		// message capacity exceeded
		pwr.stats.cnts.Dec(pwr.stats.hQueuedMsgs) // send failed -> dec
		pwr.stats.cnts.Inc(pwr.stats.hDroppedQueue)
		DBG("queue exceeded for %q\n", pwr.name)
		return false
	}
	//DBG("%q returning true\n", pwr.name)
	return true
}

func (pwr *PcapWrWorker) TotalMsgs() uint64 {
	return pwr.tmsgs.Load()
}

func (pwr *PcapWrWorker) run() bool {
loop:
	for {
		select {
		case m, ok := <-pwr.msgs:
			if !ok { // channel closed
				break loop
			}
			pwr.stats.cnts.Dec(pwr.stats.hQueuedMsgs)
			v := pwr.tmsgs.Add(1)
			// DBG("worker %s  tmsg: %d\n", pwr.name, v)
			pwr.stats.cnts.Max(pwr.stats.hMaxMsgsWorker, counters.Val(v))
			pwr.writeMsg(m)
			FreePcapWrMsg(m)
			continue
		case <-pwr.stop:
			break loop
		}
	}
	close(pwr.msgs)
	pwr.msgs = nil
	return false
}

func (pwr *PcapWrWorker) writeMsg(m PcapWrMsg) error {

	var err error
	var f *os.File
	var pcapDump *pcapgo.Writer
	var offs int64
	var ciTime time.Time

	key, flags, timestamp, content := m.Parse()
	/*
	 key := m.RawKey()
	 content := m.RawMsg()
	 flags := m.Flags()
	 timestamp := m.Timestamp()
	*/
	if len(key) == 0 {
		// error bad message
		BUG("PCAP Dumper %s: bad message flags 0%0x len %d total %d\n",
			pwr.name, flags, len(content), len(m))
		return ErrBadPcapIntMsg
	}

	//	DBG("PCAP Dumper %s: message %q flags 0x%0x  len %d\n",
	//		pwr.name, key, flags, len(content))
	if flags&PcapMsgHdrTimestampF != 0 {
		// timestamp in header
		ciTime = timestamp.Time()
	} else {
		// no timestamp in header => use current time
		ciTime = time.Now()
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      ciTime,
		CaptureLength:  len(content),
		Length:         len(content),
		InterfaceIndex: 0,
	}
	// TODO: search if fd & name cached, based on m.key
	// if not, create or open/append file
	fname, dirname := pwr.cfg.PcapFileFullPath(key)
	/*
		DBG("PCAP Dumper %s: message %q (l: %d) (h: %d seed: %d , %d) flags 0x%0x  len %d:"+
			" open file %q (%q subdir %q (%d))\n",
			pwr.name, key, len(key), pwr.cfg.Hash(key), dirSeed, pwr.cfg.Hash(nil),
			flags, len(content),
			fname, dirname, pwr.cfg.PcapFileSubDir(key),
			pwr.cfg.Hash(key)%uint64(len(pwr.cfg.subDirs)))
	*/
	for tries := 0; tries < 2; tries++ {
		if (flags & PcapDumpAppendOnlyF) != 0 {
			f, err = os.OpenFile(fname, os.O_WRONLY, 0644)
		} else {
			f, err = os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0644)
		}
		if err != nil {
			if tries == 0 && errors.Is(err, os.ErrNotExist) {
				// try to create subdir
				err = os.MkdirAll(dirname, 0700)
				if err != nil && !errors.Is(err, os.ErrExist) {
					DBG("error creating dir %q: %v (%T)\n", dirname, err, err)
					pwr.stats.cnts.Inc(pwr.stats.hErrMkSubdir)
					goto err_cleanup
				}
				DBG("PCAP Dumper %s: created dir %q for %q (file %q)\n",
					pwr.name, dirname, key, fname)
				pwr.stats.cnts.Inc(pwr.stats.hNewSubdir)
				continue // retry OpenFile
			} else {
				DBG("PCAP Dumper %s: ERROR for message %q (err type %T): %v\n",
					pwr.name, key, err, err)
				if (flags & PcapDumpAppendOnlyF) == 0 {
					// if not in append only mode => new file error
					pwr.stats.cnts.Inc(pwr.stats.hErrNewFile)
				} else {
					// non-existing file
					pwr.stats.cnts.Inc(pwr.stats.hErrAppendOnly)
				}
				goto err_cleanup
			}
		}
	}
	// seek to the end of file and get the offset
	if offs, err = f.Seek(0, os.SEEK_END); err != nil {
		DBG("PCAP Dumper %s: ERROR for message %q (err type %T): %v\n",
			pwr.name, key, err, err)
		goto err_cleanup
	}
	pcapDump = pcapgo.NewWriter(f)
	if offs == 0 {
		// new file -> write pcap header
		if flags&PcapDumpNewFileF == 0 {
			// new file not set
			DBG("PCAP Dumper %s: missing file %q -> created, writing pcap header.\n",
				pwr.name, fname)
			pwr.stats.cnts.Inc(pwr.stats.hNewMissingFile)
		}
		pwr.stats.cnts.Inc(pwr.stats.hNewFile)
		err = pcapDump.WriteFileHeader(65536, layers.LinkTypeEthernet)
		if err != nil {
			DBG("PCAP Dumper %s: ERROR for message %q (err type %T): %v\n",
				pwr.name, key, err, err)
			pwr.stats.cnts.Inc(pwr.stats.hErrWrHdr)
			goto err_cleanup
		}
	} else if flags&PcapDumpNewFileF != 0 {
		DBG("PCAP Dumper %s: new file requested (now %v ts %v ),"+
			" but file %q already present\n",
			time.Now(), ciTime, pwr.name, fname)
		pwr.stats.cnts.Inc(pwr.stats.hFileExists)
	}
	err = pcapDump.WritePacket(ci, content)
	if err != nil {
		DBG("PCAP Dumper %s: ERROR for message %q (err type %T): %v\n",
			pwr.name, key, err, err)
		pwr.stats.cnts.Inc(pwr.stats.hErrWrMsg)
		goto err_cleanup
	}
	pwr.stats.cnts.Inc(pwr.stats.hWrittenMsgs)
	pwr.stats.cnts.Add(pwr.stats.hWrittenBytes,
		counters.Val(len(content)))

	// TODO: add to cache if new
	// TODO: don't open/close file every time
err_cleanup:
	if f != nil {
		f.Close()
	}

	if err != nil {
		pwr.stats.cnts.Inc(pwr.stats.hDroppedWr)
		DBG("PCAP Dumper %s: ERROR for message %q flags 0x%0x  len %d type %T"+
			": %v\n",
			pwr.name, key, flags, len(content), err, err)
	}
	return err
}
