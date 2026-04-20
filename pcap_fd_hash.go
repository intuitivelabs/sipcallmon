package sipcallmon

// Per-worker file descriptor hash table for pcap writer.
// Uses double-linked lists for bucket chaining (same pattern as
// calltr/callentry_lst.go). No locking needed since each hash table is
// local to a single worker goroutine.

import (
	"bytes"
	"os"

	"github.com/google/gopacket/pcapgo"

	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/wtimer"
)

// hash functions from calltr/hash.go
func pcapFdGetHash(buf []byte) uint32 {
	return calltr.GetHash(buf, 0, len(buf))
}

const pcapFdMaxKeyLen = 256
const pcapFdMaxFnameLen = 256

const pcapFdPoolEntryF uint8 = 1 // entry came from pre-alloc pool

// pcapFdEntry is a tracked open pcap file descriptor.
// (stored in a hash bucket double linked list)
type pcapFdEntry struct {
	// bucket list pointers
	next *pcapFdEntry
	prev *pcapFdEntry
	// LTimer link for per-entry expiry
	timer wtimer.LTimerLnk
	// back pointer to owning tracker (set once at alloc time)
	tracker *pcapFdTracker
	// file handle and pcap writer
	f     *os.File
	pcapW *pcapgo.Writer
	nWritten uint32 // number of packets written (0 => empty, skip rename)
	state    uint8
	flags    uint8
	// key stored inline (SIP Call-IDs < 256 bytes)
	keyLen uint16
	key    [pcapFdMaxKeyLen]byte
	// cached filename for rename-on-close
	fnameLen uint16
	fname    [pcapFdMaxFnameLen]byte
}

// pcapFdBucket is a hash bucket with a double linked list.
type pcapFdBucket struct {
	head    pcapFdEntry // sentinel, only next/prev used
	entries uint
}

func (b *pcapFdBucket) Init() {
	b.head.next = &b.head
	b.head.prev = &b.head
	b.entries = 0
}

func (b *pcapFdBucket) Insert(e *pcapFdEntry) {
	e.prev = &b.head
	e.next = b.head.next
	e.next.prev = e
	b.head.next = e
	b.entries++
}

func (b *pcapFdBucket) Rm(e *pcapFdEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = e
	e.prev = e
	b.entries--
}

func (b *pcapFdBucket) Detached(e *pcapFdEntry) bool {
	return e == e.next
}

// ForEachSafeRm iterates the bucket list, safe for removal of current element.
func (b *pcapFdBucket) ForEachSafeRm(f func(e *pcapFdEntry)) {
	s := b.head.next
	for v, nxt := s, s.next; v != &b.head; v, nxt = nxt, nxt.next {
		f(v)
	}
}

// pcapFdHash is a hash table of pcapFdEntry, with a free list for
// pre-allocated entries.
type pcapFdHash struct {
	buckets  []pcapFdBucket
	free     pcapFdBucket  // free list (reuses bucket as list container)
	pool     []pcapFdEntry // backing array for pre-allocated entries
	nEntries uint          // current number of active entries
	size     uint          // number of buckets
}

func (h *pcapFdHash) Init(buckets, prealloc int) {
	h.size = uint(buckets)
	h.buckets = make([]pcapFdBucket, buckets)
	for i := range h.buckets {
		h.buckets[i].Init()
	}
	h.free.Init()
	// pre-allocate entries into the free list
	if prealloc > 0 {
		h.pool = make([]pcapFdEntry, prealloc)
		for i := range h.pool {
			e := &h.pool[i]
			e.next = e
			e.prev = e
			e.flags = pcapFdPoolEntryF
			h.free.Insert(e)
		}
	}
}

func (h *pcapFdHash) hash(key []byte) uint32 {
	return pcapFdGetHash(key) % uint32(h.size)
}

// Lookup finds an entry by key. Returns nil if not found.
func (h *pcapFdHash) Lookup(key []byte) *pcapFdEntry {
	idx := h.hash(key)
	b := &h.buckets[idx]
	for e := b.head.next; e != &b.head; e = e.next {
		if int(e.keyLen) == len(key) && bytes.Equal(e.key[:e.keyLen], key) {
			return e
		}
	}
	return nil
}

// Insert adds an entry to the appropriate bucket based on its key.
func (h *pcapFdHash) Insert(e *pcapFdEntry) {
	idx := h.hash(e.key[:e.keyLen])
	h.buckets[idx].Insert(e)
	h.nEntries++
}

// Remove removes an entry from its bucket.
func (h *pcapFdHash) Remove(e *pcapFdEntry) {
	idx := h.hash(e.key[:e.keyLen])
	h.buckets[idx].Rm(e)
	h.nEntries--
}

// Alloc returns an entry from the free list, or allocates a new one.
func (h *pcapFdHash) Alloc() *pcapFdEntry {
	if h.free.entries > 0 {
		e := h.free.head.next
		h.free.Rm(e)
		return e
	}
	// free list empty, allocate new
	e := new(pcapFdEntry)
	e.next = e
	e.prev = e
	return e
}

// Free returns an entry to the free list after clearing it.
// Heap-allocated entries (not from pool) are dropped when the free list
// is already well-stocked (>= pool size), letting GC reclaim them.
// Returns true if the entry was a heap entry (for stats tracking).
func (h *pcapFdHash) Free(e *pcapFdEntry) bool {
	isPool := e.flags&pcapFdPoolEntryF != 0
	e.f = nil
	e.pcapW = nil
	e.state = 0
	e.nWritten = 0
	e.keyLen = 0
	e.fnameLen = 0
	// do not clear tracker pointer, it stays valid
	if isPool {
		e.flags = pcapFdPoolEntryF // preserve pool flag
		h.free.Insert(e)
		return false
	}
	e.flags = 0
	// heap entry: only keep if free list is below pool size
	if h.free.entries < uint(len(h.pool)) {
		h.free.Insert(e)
	}
	// else: drop entry, let GC collect it
	return true
}

// ForEachSafeRm iterates all entries across all buckets, safe for removal.
func (h *pcapFdHash) ForEachSafeRm(f func(e *pcapFdEntry)) {
	for i := uint(0); i < h.size; i++ {
		h.buckets[i].ForEachSafeRm(f)
	}
}
