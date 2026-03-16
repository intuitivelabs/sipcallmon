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

// pcapRotFmtOp identifies a format segment operation for rotated filenames.
type pcapRotFmtOp uint8

const (
	rotFmtLiteral       pcapRotFmtOp = iota // literal bytes
	rotFmtBase                              // %b - original base (no ext)
	rotFmtExt                               // %e - original extension
	rotFmtFull                              // %f - original filename
	rotFmtDir                               // %d - original directory
	rotFmtTsSec                             // %s - unix seconds
	rotFmtTsMs                              // %ms - unix milliseconds
	rotFmtTsNs                              // %ns - unix nanoseconds
	rotFmtTimeLayout                        // %t{layout} - Go time format
	rotFmtRand                              // %r - random hex uint32 (always)
	rotFmtUploadId                          // %i - PcapUploadId(key)
	rotFmtSeq                               // %n - monotonic counter (always)
	rotFmtConflictRand                      // %R - random hex (conflict-only)
	rotFmtConflictSeq                       // %N - monotonic counter (conflict-only)
	rotFmtConflictRetry                     // %U - retry counter (conflict-only)
)

// pcapRotFmtSeg is one segment of a compiled rotate format string.
type pcapRotFmtSeg struct {
	op  pcapRotFmtOp
	lit string // literal text or time layout
}

type pcapFdTracker struct {
	h              pcapFdHash
	lt             wtimer.LTimer
	rotateInterval time.Duration
	rotateSuffix   string           // new extension on close (e.g. ".pcap")
	rotateDir      string           // move to this dir on close
	rotateFmt      []pcapRotFmtSeg  // compiled format (parsed once at Init)
	maxOpen        int64            // global limit on tracked entries (0 = unlimited)
	cfg            *PcapWriterCfg   // needed for PcapUploadId (%i)
	stats          *pcapStatsT
	rng            uint32           // xorshift32 state for %r / %R
	seq            uint64           // monotonic counter for %n / %N
	hasRetryOp     bool             // true if format contains %R, %N, or %U
}

func (t *pcapFdTracker) Init(buckets, prealloc, maxOpen int,
	rotateInterval time.Duration, rotateSuffix, rotateDir, rotateFmt string,
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
	t.rotateFmt, t.hasRetryOp = parseRotateFmt(rotateFmt)
	// if no explicit format, use default that matches old behavior
	if len(t.rotateFmt) == 0 {
		t.rotateFmt, t.hasRetryOp = parseRotateFmt("%b_%s%e")
	}
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

// RotateActive returns true if in rotate mode.
func (t *pcapFdTracker) RotateActive() bool {
	return len(t.rotateFmt) > 0 || len(t.rotateSuffix) > 0 || len(t.rotateDir) > 0
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

// rotateEntry closes, renames (if non-empty), removes from hash, and frees.
func (t *pcapFdTracker) rotateEntry(e *pcapFdEntry) {
	if e.f != nil {
		e.f.Close()
		e.f = nil
		e.pcapW = nil
	}
	// rename/move only if file has actual packet data
	if e.nWritten > 0 && t.RotateActive() {
		t.renameFile(e.fname[:e.fnameLen], e.key[:e.keyLen])
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
func (t *pcapFdTracker) renameFile(oldName []byte, key []byte) {
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
}

// buildNewName constructs the rotated filename by iterating the compiled
// format segments. All operations append to buf (stack-allocated by caller).
// retry is 0 on first attempt; >0 on conflict retries (for %R, %N, %U).
func (t *pcapFdTracker) buildNewName(buf []byte, oldName []byte,
	key []byte, retry int) []byte {

	// parse oldName into dir, base, ext once
	dir, baseName, ext := splitOldName(oldName)

	now := time.Now()

	for i := range t.rotateFmt {
		seg := &t.rotateFmt[i]
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
		case rotFmtDir:
			if len(t.rotateDir) > 0 {
				buf = append(buf, t.rotateDir...)
				if t.rotateDir[len(t.rotateDir)-1] != '/' {
					// add '/' if rotateDir does not end with it
					// and next chunk is not a literal starting with it
					if (i+1) >= len(t.rotateFmt) ||
						t.rotateFmt[i+1].op != rotFmtLiteral ||
						(len(t.rotateFmt[i+1].lit) == 0) ||
						t.rotateFmt[i+1].lit[0] != '/' {
							buf = append(buf, '/')
					}
				}
			} else if len(dir) > 0 {
				buf = append(buf, dir...)
				// add '/' if next chunk is not a literal starting with it
				if (i+1) >= len(t.rotateFmt) ||
					t.rotateFmt[i+1].op != rotFmtLiteral ||
					(len(t.rotateFmt[i+1].lit) == 0) ||
					t.rotateFmt[i+1].lit[0] != '/' {
						buf = append(buf, '/')
				}
			}
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

// splitOldName splits oldName into directory (without trailing /),
// base name (without extension), and extension (with leading dot).
// All returned slices point into oldName (no allocation).
func splitOldName(oldName []byte) (dir, baseName, ext []byte) {
	// find last '/' for dir/base split
	dirEnd := -1
	for i := len(oldName) - 1; i >= 0; i-- {
		if oldName[i] == '/' {
			dirEnd = i
			break
		}
	}

	var base []byte
	if dirEnd >= 0 {
		dir = oldName[:dirEnd]
		base = oldName[dirEnd+1:]
	} else {
		base = oldName
	}

	// find last '.' in base for extension split
	extIdx := -1
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '.' {
			extIdx = i
			break
		}
	}
	if extIdx >= 0 {
		baseName = base[:extIdx]
		ext = base[extIdx:]
	} else {
		baseName = base
	}
	return
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

// appendHex32 appends v as 8 lowercase hex digits to buf (zero-alloc).
func appendHex32(buf []byte, v uint32) []byte {
	const hexDigits = "0123456789abcdef"
	var tmp [8]byte
	for i := 7; i >= 0; i-- {
		tmp[i] = hexDigits[v&0xf]
		v >>= 4
	}
	return append(buf, tmp[:]...)
}

// parseRotateFmt compiles a format string into a list of segments.
// Returns nil if the format string is empty.
// Also returns whether any conflict-only ops (%R, %N, %U) are present.
func parseRotateFmt(fmt string) ([]pcapRotFmtSeg, bool) {
	if len(fmt) == 0 {
		return nil, false
	}
	var segs []pcapRotFmtSeg
	hasRetry := false
	litStart := 0
	i := 0
	for i < len(fmt) {
		if fmt[i] != '%' {
			i++
			continue
		}
		// flush literal before this %
		if i > litStart {
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: fmt[litStart:i]})
		}
		i++ // skip '%'
		if i >= len(fmt) {
			break
		}
		switch fmt[i] {
		case '%':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%"})
			i++
		case 'b':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtBase})
			i++
		case 'e':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtExt})
			i++
		case 'f':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtFull})
			i++
		case 'd':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtDir})
			i++
		case 's':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtTsSec})
			i++
		case 'm':
			// %ms
			if i+1 < len(fmt) && fmt[i+1] == 's' {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtTsMs})
				i += 2
			} else {
				// unknown, treat as literal
				segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%m"})
				i++
			}
		case 'n':
			// %ns or %n
			if i+1 < len(fmt) && fmt[i+1] == 's' {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtTsNs})
				i += 2
			} else {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtSeq})
				i++
			}
		case 't':
			// %t{layout}
			i++
			if i < len(fmt) && fmt[i] == '{' {
				end := i + 1
				for end < len(fmt) && fmt[end] != '}' {
					end++
				}
				if end < len(fmt) {
					layout := fmt[i+1 : end]
					segs = append(segs, pcapRotFmtSeg{op: rotFmtTimeLayout, lit: layout})
					i = end + 1
				} else {
					// unterminated {, treat as literal
					segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%t"})
				}
			} else {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%t"})
			}
		case 'r':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtRand})
			i++
		case 'i':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtUploadId})
			i++
		case 'R':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictRand})
			hasRetry = true
			i++
		case 'N':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictSeq})
			hasRetry = true
			i++
		case 'U':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictRetry})
			hasRetry = true
			i++
		default:
			// unknown specifier, emit as literal
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral,
				lit: fmt[i-1 : i+1]})
			i++
		}
		litStart = i
	}
	// flush trailing literal
	if litStart < len(fmt) {
		segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: fmt[litStart:]})
	}
	return segs, hasRetry
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
