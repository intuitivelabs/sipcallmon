package sipcallmon

// Per-worker FD tracker: wraps pcapFdHash + wtimer.LTimer for
// automatic rotation (close + rename/move) of pcap files at a fixed interval.
// No locking needed (single goroutine per worker).
//
// The timer is a rotation timer: it fires once after the configured interval
// from when the file was first opened. On fire: close file, rename/move it
// (if non-empty), remove from tracker. Next packet creates a new file.

import (
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket/pcapgo"
	"github.com/intuitivelabs/timestamp"
	"github.com/intuitivelabs/unsafeconv"
	"github.com/intuitivelabs/wtimer"
)

type pcapFdTracker struct {
	h              pcapFdHash
	lt             wtimer.LTimer
	rotateInterval time.Duration
	rotateSuffix   string          // new extension on close (e.g. ".pcap")
	rotateDir      string          // move to this dir on close
	maxOpen        int64           // global limit on tracked entries (0 = unlimited)
	cfg            *PcapWriterCfg  // needed for PcapUploadId (%i) and rotateFmtSegs
	stats          *pcapStatsT
	rng            uint32          // xorshift32 state for %r / %R
	seq            uint64          // monotonic counter for %n / %N
	hasRetryOp     bool            // true if format contains %R, %N, or %U
	// file uploader: set externally after Init() if upload is configured
	upldCh   chan<- *pcapFileUpldReq // nil if channel upload disabled
	upldPool *pcapFileUpldPool       // nil if channel upload disabled
}

func (t *pcapFdTracker) Init(buckets, prealloc, maxOpen int,
	rotateInterval time.Duration, rotateSuffix, rotateDir string,
	cfg *PcapWriterCfg, stats *pcapStatsT) error {

	t.h.Init(buckets, prealloc)
	t.rotateInterval = rotateInterval
	t.rotateSuffix = rotateSuffix
	t.rotateDir = rotateDir
	t.maxOpen = int64(maxOpen)
	t.cfg = cfg
	t.stats = stats
	t.rng = uint32(time.Now().UnixNano())
	if t.rng == 0 {
		t.rng = 1 // xorshift32 must not be 0
	}
	t.hasRetryOp = cfg.rotateFmtHasRetry
	// tick duration: use 100ms for reasonable timer resolution
	// (10s interval = 100 ticks)
	err := t.lt.Init(100 * time.Millisecond)
	if err != nil {
		return err
	}
	// set all pre-allocated entries' tracker pointer
	for i := range t.h.pool {
		t.h.pool[i].tracker = t
	}
	return nil
}

// rotateFmt returns the compiled format segments from cfg.
func (t *pcapFdTracker) rotateFmt() []pcapRotFmtSeg {
	return t.cfg.rotateFmtSegs
}

// RotateActive returns true if in rotate mode.
func (t *pcapFdTracker) RotateActive() bool {
	return len(t.cfg.rotateFmtSegs) > 0 || len(t.rotateSuffix) > 0 || len(t.rotateDir) > 0
}

// Lookup finds a tracked entry by key.
func (t *pcapFdTracker) Lookup(key []byte) *pcapFdEntry {
	return t.h.Lookup(key)
}

// Add creates a new tracked entry, inserts it into the hash table,
// and starts a rotation timer for it. The timer fires once after
// rotateInterval; it is not reset on subsequent writes.
func (t *pcapFdTracker) Add(key, fname []byte, f *os.File,
	pcapW *pcapgo.Writer, now timestamp.TS) *pcapFdEntry {

	// enforce global limit via shared atomic counter
	if t.stats != nil {
		n := t.stats.cnts.Inc(t.stats.hFdTrackEntries)
		if t.maxOpen > 0 && int64(n) > t.maxOpen {
			t.stats.cnts.Dec(t.stats.hFdTrackEntries)
			return nil // at global limit
		}
	}
	e := t.h.Alloc()
	e.tracker = t
	e.f = f
	e.pcapW = pcapW
	e.state = 1 // open
	e.nWritten = 0
	e.openTS = time.Now().Unix()
	kl := len(key)
	if kl > pcapFdMaxKeyLen {
		kl = pcapFdMaxKeyLen
	}
	e.keyLen = uint16(copy(e.key[:], key[:kl]))
	fl := len(fname)
	if fl > pcapFdMaxFnameLen {
		fl = pcapFdMaxFnameLen
	}
	e.fnameLen = uint16(copy(e.fname[:], fname[:fl]))
	// track heap alloc (pool entries have pcapFdPoolEntryF set)
	if t.stats != nil && e.flags&pcapFdPoolEntryF == 0 {
		t.stats.cnts.Inc(t.stats.hFdTrackHeapAlloc)
	}
	t.h.Insert(e)

	// start rotation timer (fires once, not reset on writes)
	t.lt.InitTimer(&e.timer)
	t.lt.Add(&e.timer, t.rotateInterval, now, pcapFdTimerHandler, e)
	return e
}

// RunTimers advances the LTimer, firing callbacks for expired entries.
func (t *pcapFdTracker) RunTimers(now timestamp.TS) {
	t.lt.Run(now)
}

// CloseAll closes and renames all tracked entries (graceful shutdown).
func (t *pcapFdTracker) CloseAll() {
	t.h.ForEachSafeRm(func(e *pcapFdEntry) {
		// delete timer if still active
		t.lt.Del(&e.timer)
		t.lt.ResetTimer(&e.timer)
		t.rotateEntry(e)
	})
}

// CloseEntry forces close+rotate of the tracked entry matching key.
// No-op if key is not tracked.
func (t *pcapFdTracker) CloseEntry(key []byte) {
	e := t.h.Lookup(key)
	if e == nil {
		return
	}
	t.lt.Del(&e.timer)
	t.lt.ResetTimer(&e.timer)
	t.rotateEntry(e)
}

// rotateEntry closes, renames (if non-empty), removes from hash, and frees.
func (t *pcapFdTracker) rotateEntry(e *pcapFdEntry) {
	if e.f != nil {
		e.f.Close()
		e.f = nil
		e.pcapW = nil
	}
	// rename/move only if file has actual packet data
	if e.nWritten > 0 && t.RotateActive() {
		t.renameFile(e.fname[:e.fnameLen], e.key[:e.keyLen],
			e.openTS, time.Now().Unix())
	}
	e.state = 0
	t.h.Remove(e)
	wasHeap := t.h.Free(e)
	if t.stats != nil {
		t.stats.cnts.Inc(t.stats.hFdTrackRotations)
		t.stats.cnts.Dec(t.stats.hFdTrackEntries)
		if wasHeap {
			t.stats.cnts.Inc(t.stats.hFdTrackHeapFree)
		}
	}
}

// renameFile renames/moves a closed pcap file using the compiled format.
// oldName and key are byte slices (no alloc).
// fromTS/toTS are unix seconds for upload timestamps (0 = derive from file).
func (t *pcapFdTracker) renameFile(oldName []byte, key []byte,
	fromTS, toTS int64) {
	var buf [512]byte

	newName := t.buildNewName(buf[:0], oldName, key, 0)
	if len(newName) == 0 {
		return
	}
	oldStr := unsafeconv.Str(oldName)
	newStr := unsafeconv.Str(newName)
	err := os.Rename(oldStr, newStr)

	// handle target dir not existing
	if err != nil && errors.Is(err, os.ErrNotExist) && len(t.rotateDir) > 0 {
		mkErr := os.MkdirAll(t.rotateDir, 0700)
		if mkErr == nil {
			err = os.Rename(oldStr, newStr)
		}
	}

	// handle name conflict: retry only if format contains %R, %N, or %U
	if err != nil && errors.Is(err, os.ErrExist) && t.hasRetryOp {
		if t.stats != nil {
			t.stats.cnts.Inc(t.stats.hFdTrackNameConflict)
		}
		for retry := 1; retry <= 99; retry++ {
			newName = t.buildNewName(buf[:0], oldName, key, retry)
			newStr = unsafeconv.Str(newName)
			err = os.Rename(oldStr, newStr)
			if err == nil || !errors.Is(err, os.ErrExist) {
				break
			}
		}
	}

	if err != nil {
		ERR("pcap fd tracker: rename %q -> %q: %v\n", oldStr, newStr, err)
		if t.stats != nil {
			t.stats.cnts.Inc(t.stats.hErrFdTrackRename)
		}
		return
	}
	if t.stats != nil {
		t.stats.cnts.Inc(t.stats.hFdTrackRenames)
	}
	// notify file uploader (non-blocking)
	if t.upldCh != nil {
		t.sendUpldReq(newName, key, fromTS, toTS)
	}
}

// buildNewName constructs the rotated filename by iterating the compiled
// format segments. All operations append to buf (stack-allocated by caller).
// retry is 0 on first attempt; >0 on conflict retries (for %R, %N, %U).
func (t *pcapFdTracker) buildNewName(buf []byte, oldName []byte,
	key []byte, retry int) []byte {

	baseName, ext := splitOldName(oldName)

	now := time.Now()
	segs := t.rotateFmt()

	for i := range segs {
		seg := &segs[i]
		switch seg.op {
		case rotFmtLiteral:
			buf = append(buf, seg.lit...)
		case rotFmtBase:
			buf = append(buf, baseName...)
		case rotFmtExt:
			if len(t.rotateSuffix) > 0 {
				if t.rotateSuffix[0] != '.' &&
					(len(buf)> 0 && buf[len(buf)-1] != '.') {
					// add '.' if rotateSuffix does not start with it and
					// buf does not end with it
					buf = append(buf, '.')
				}
				buf = append(buf, t.rotateSuffix...)
			} else {
				if (len(buf)> 0 && buf[len(buf)-1] == '.' && len(ext) > 0) {
					// skip over '.' if already present in buf
					buf = append(buf, ext[1:]...)
				} else {
					buf = append(buf, ext...)
				}
			}
		case rotFmtFull:
			buf = append(buf, baseName...)
			buf = append(buf, ext...)
		case rotFmtTsSec:
			buf = strconv.AppendInt(buf, now.Unix(), 10)
		case rotFmtTsMs:
			buf = strconv.AppendInt(buf, now.UnixMilli(), 10)
		case rotFmtTsNs:
			buf = strconv.AppendInt(buf, now.UnixNano(), 10)
		case rotFmtTimeLayout:
			buf = now.AppendFormat(buf, seg.lit)
		case rotFmtRand:
			buf = appendHex32(buf, t.nextRand())
		case rotFmtUploadId:
			if t.cfg != nil {
				// PcapUploadId writes into dst; ensure enough room
				avail := cap(buf) - len(buf)
				if avail < 128 {
					// shouldn't happen with 512 byte buf, but be safe
					break
				}
				n, err := t.cfg.PcapUploadId(buf[len(buf):cap(buf)], key)
				if err == nil {
					buf = buf[:len(buf)+n]
				}
			}
		case rotFmtSeq:
			if retry == 0 {
				buf = strconv.AppendUint(buf, t.seq, 10)
				t.seq++
			} else {
				// on retries, re-emit the same seq value (already incremented)
				buf = strconv.AppendUint(buf, t.seq-1, 10)
			}
		case rotFmtConflictRand:
			if retry > 0 {
				buf = append(buf, '_')
				buf = appendHex32(buf, t.nextRand())
			}
		case rotFmtConflictSeq:
			if retry > 0 {
				buf = append(buf, '_')
				if retry == 1 {
					buf = strconv.AppendUint(buf, t.seq, 10)
					t.seq++
				} else {
					// re-emit same seq on subsequent retries
					buf = strconv.AppendUint(buf, t.seq-1, 10)
				}
			}
		case rotFmtConflictRetry:
			if retry > 0 {
				buf = append(buf, '_')
				buf = strconv.AppendInt(buf, int64(retry), 10)
			}
		}
	}
	// TODO: if buf does not include any directory, prepend dir
	return buf
}

// nextRand returns a pseudo-random uint32 using xorshift32.
// Single goroutine per tracker, no synchronization needed.
func (t *pcapFdTracker) nextRand() uint32 {
	x := t.rng
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 5
	t.rng = x
	return x
}

// pcapFdTimerHandler is the LTimer callback fired when a rotation
// timer expires. It closes, renames, and frees the entry.
func pcapFdTimerHandler(lt *wtimer.LTimer, tl *wtimer.LTimerLnk,
	arg interface{}) (bool, time.Duration) {
	e := arg.(*pcapFdEntry)
	e.tracker.rotateEntry(e)
	return false, 0 // don't re-arm
}

// Entries returns the current number of tracked entries.
func (t *pcapFdTracker) Entries() uint {
	return t.h.nEntries
}

// sendUpldReq gets a request from the pool, fills it, and sends
// to the upload channel (non-blocking).
func (t *pcapFdTracker) sendUpldReq(newName, key []byte,
	fromTS, toTS int64) {
	req := t.upldPool.Get()
	if req == nil {
		// pool exhausted — file stays in rotate dir
		return
	}
	req.fnameLen = uint16(copy(req.fname[:], newName))
	n, err := t.cfg.PcapUploadId(req.upldId[:], key)
	if err != nil {
		t.upldPool.Put(req)
		return
	}
	req.idLen = uint16(n)
	req.fromTS = fromTS
	req.toTS = toTS
	select {
	case t.upldCh <- req:
	default:
		t.upldPool.Put(req) // queue full
	}
}
