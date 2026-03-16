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
	rotateSuffix   string // new extension on close (e.g. ".pcap")
	rotateDir      string // move to this dir on close
	maxOpen        int64  // global limit on tracked entries (0 = unlimited)
	stats          *pcapStatsT
}

func (t *pcapFdTracker) Init(buckets, prealloc, maxOpen int,
	rotateInterval time.Duration, rotateSuffix, rotateDir string,
	stats *pcapStatsT) error {

	t.h.Init(buckets, prealloc)
	t.rotateInterval = rotateInterval
	t.rotateSuffix = rotateSuffix
	t.rotateDir = rotateDir
	t.maxOpen = int64(maxOpen)
	t.stats = stats
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

// RotateActive returns true if in rotate mode
func (t* pcapFdTracker) RotateActive() bool {

	return (len(t.rotateSuffix) > 0) || (len(t.rotateDir) > 0)
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
		t.renameFile(e.fname[:e.fnameLen])
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

// renameFile renames/moves a closed pcap file, appending a unix timestamp
// to the filename to avoid overwrites. oldName is a byte slice (no alloc).
func (t *pcapFdTracker) renameFile(oldName []byte) {
	var buf [512]byte

	newName := t.buildNewName(buf[:0], oldName)
	if len(newName) == 0 {
		return
	}
	// use unsafeconv to avoid allocations for os.Rename args
	oldStr := unsafeconv.Str(oldName)
	newStr := unsafeconv.Str(newName)
	err := os.Rename(oldStr, newStr)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && len(t.rotateDir) > 0 {
			// target directory may not exist yet, create it and retry
			mkErr := os.MkdirAll(t.rotateDir, 0700)
			if mkErr == nil {
				err = os.Rename(oldStr, newStr)
			}
		}
	}
	if err != nil {
		// TODO: if failed because the new name already exists => try
		// adding a version to the name and retry; also increase a counter
		// for name conflicts
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

// buildNewName constructs the new filename with timestamp and new extension.
// Uses the provided buf to avoid heap allocation.
// Format: <dir>/<base_without_ext>_<unix_ts><new_suffix>
// If rotateDir is set, replaces the directory.
// oldName is a byte slice; all operations avoid string conversion.
// TODO: have an option to create a subdir under t.rotateDir if the
//  subdir mode for the files is enabled
func (t *pcapFdTracker) buildNewName(buf []byte, oldName []byte) []byte {
	// find last '/' for dir/base split
	dirEnd := -1
	for i := len(oldName) - 1; i >= 0; i-- {
		if oldName[i] == '/' {
			dirEnd = i
			break
		}
	}

	var dir []byte
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
	var baseName []byte
	if extIdx >= 0 {
		baseName = base[:extIdx]
	} else {
		baseName = base
	}

	// determine new extension
	newExt := t.rotateSuffix
	if len(newExt) == 0 && extIdx >= 0 {
		newExt = unsafeconv.Str(base[extIdx:])
	}

	// determine new directory
	if len(t.rotateDir) > 0 {
		buf = append(buf, t.rotateDir...)
		if t.rotateDir[len(t.rotateDir)-1] != '/' {
			buf = append(buf, '/')
		}
	} else if len(dir) > 0 {
		buf = append(buf, dir...)
		buf = append(buf, '/')
	}
	buf = append(buf, baseName...)
	buf = append(buf, '_')
	// TODO: switch to UnixMilli(), UnixMicro() or UnixNano()
	buf = strconv.AppendInt(buf, time.Now().Unix(), 10)
	if len(newExt) > 0 {
		if newExt[0] != '.' {
			buf = append(buf, '.')
		}
		buf = append(buf, newExt...)
	}
	return buf
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
