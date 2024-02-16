package sipcallmon

import (
	"errors"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/sipsp"
)

const (
	PcapDumpAppendDefF  PcapWrMsgFlags = 0
	PcapDumpAppendOnlyF PcapWrMsgFlags = 1
)

type PcapWrMsgFlags uint32

// internal format:
//
//	key - sipsp.PField (offs & len for the key)
//	flags - uint32
//	msg - bytes array
type PcapWrMsg []byte

func NewPcapWrMsg(Key sipsp.PField, flags PcapWrMsgFlags,
	msg []byte) PcapWrMsg {
	offsFlags := int(unsafe.Sizeof(Key))
	// offset to start of message
	offs := int(unsafe.Sizeof(Key) + unsafe.Sizeof(flags))
	sz := offs + len(msg)
	if Key.Len == 0 || (int(uint(Key.Offs)+uint(Key.Len)) > len(msg)) {
		// invalid key or msg
		return nil
	}
	// TODO: switch to "github.com/intuitivelabs/bytespool"
	buf := make([]byte, sz)

	pkey := (*sipsp.PField)(unsafe.Pointer(&buf[0]))
	*pkey = Key
	pflags := (*PcapWrMsgFlags)(unsafe.Pointer(&buf[offsFlags]))
	*pflags = flags
	copy(buf[offs:], msg)
	pcapStats.cnts.Inc(pcapStats.hAllocMsgs)
	pcapStats.cnts.Add(pcapStats.hAllocBytes, counters.Val(sz))
	return PcapWrMsg(buf)
}

func FreePcapWrMsg(pwm *PcapWrMsg) {
	// TODO: counters
	// TODO: put back into pool (after switching to bytespool)
	sz := len(*pwm)
	*pwm = []byte{}
	pcapStats.cnts.Dec(pcapStats.hAllocMsgs)
	pcapStats.cnts.Sub(pcapStats.hAllocBytes, counters.Val(sz))
}

// Format: key offs (2 bytes), key len (2 bytes), message ...
//Key     sipsp.PField
//Content []byte

func (pwm PcapWrMsg) RawKey() []byte {
	var k sipsp.PField

	if len(pwm) < (int(unsafe.Sizeof(k)) + 10) {
		// too small, no key
		return nil
	}
	k = *(*sipsp.PField)(unsafe.Pointer(&pwm[0]))
	buf := pwm.RawMsg()
	return k.Get(buf)
}

func (pwm PcapWrMsg) RawMsg() []byte {
	var k sipsp.PField
	var f PcapWrMsgFlags

	offs := int(unsafe.Sizeof(k) + unsafe.Sizeof(f))
	if len(pwm) < offs {
		// too small
		return nil
	}
	b := pwm[offs:]
	return b
}

func (pwm PcapWrMsg) Flags() PcapWrMsgFlags {
	var k sipsp.PField
	var f PcapWrMsgFlags

	offs := int(unsafe.Sizeof(k))
	if len(pwm) < offs {
		// too small
		return 0
	}
	f = *(*PcapWrMsgFlags)(unsafe.Pointer(&pwm[offs]))
	return f
}

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
	DBG("PcapWrWorker Stop() called: init %v\n", pwr.init)
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
	select {
	case pwr.msgs <- m:
		pwr.stats.cnts.Inc(pwr.stats.hTQueuedMsgs)
		pwr.stats.cnts.Inc(pwr.stats.hQueuedMsgs)
		//DBG("message queued to %q\n", pwr.name)
		break
	default:
		// message capacity exceeded
		pwr.stats.cnts.Inc(pwr.stats.hDroppedQueue)
		DBG("queue exceeded for %q\n", pwr.name)
		return false
	}
	//DBG("%q returning true\n", pwr.name)
	return true
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
			pwr.writeMsg(m)
			FreePcapWrMsg(&m)
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

	key := m.RawKey()
	content := m.RawMsg()
	flags := m.Flags()

	DBG("PCAP Dumper %s: message %q flags 0x%0x  len %d\n",
		pwr.name, key, flags, len(content))
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Now(), // TODO: get if from packet when available
		CaptureLength:  len(content),
		Length:         len(content),
		InterfaceIndex: 0,
	}
	// TODO: search if fd & name cached, based on m.key
	// if not, create or open/append file
	fname, dirname := pwr.cfg.PcapFileFullPath(key)
	DBG("PCAP Dumper %s: message %q flags 0x%0x  len %d: open file %q (%q)\n",
		pwr.name, key, flags, len(content), fname, dirname)
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
					DBG("error creating dir %q: %v (%T)\n", dirname, err)
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
					pwr.stats.cnts.Inc(pwr.stats.hErrNoFile)
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
		pwr.stats.cnts.Inc(pwr.stats.hNewFile)
		err = pcapDump.WriteFileHeader(65536, layers.LinkTypeEthernet)
		if err != nil {
			DBG("PCAP Dumper %s: ERROR for message %q (err type %T): %v\n",
				pwr.name, key, err, err)
			pwr.stats.cnts.Inc(pwr.stats.hErrWrHdr)
			goto err_cleanup
		}
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
