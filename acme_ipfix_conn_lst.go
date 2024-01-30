package sipcallmon

import (
	"sync"
)

type AcmeIPFIXconnLst struct {
	head AcmeIPFIXconn // used only as list head

	lock sync.Mutex
}

// Init initialises a list head
func (lst *AcmeIPFIXconnLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
}

func (lst *AcmeIPFIXconnLst) Lock() {
	lst.lock.Lock()
}

func (lst *AcmeIPFIXconnLst) Unlock() {
	lst.lock.Unlock()
}

func (lst *AcmeIPFIXconnLst) InsertUnsafe(e *AcmeIPFIXconn) {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
}

func (lst *AcmeIPFIXconnLst) RmUnsafe(e *AcmeIPFIXconn) {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
}

// ForEach iterates  on the entire lists calling f(e) for each element,
// until f() returns false or the lists ends.
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
// WARNING: does not support removing the current element from f, see
//
//	ForEachSafeRm().
func (lst *AcmeIPFIXconnLst) ForEachUnsafe(f func(e *AcmeIPFIXconn) bool) {
	cont := true
	for v := lst.head.next; v != &lst.head && cont; v = v.next {
		cont = f(v)
	}

}

// ForEachSafeRm is similar to ForEach(), but it is safe to
// remove the current entry from the function f()
// It does not Lock() the list, so make sure the list is locked if the
// code can be executed in parallel.
func (lst *AcmeIPFIXconnLst) ForEachSafeRmUnlocked(
	f func(e *AcmeIPFIXconn, l *AcmeIPFIXconnLst) bool) {
	cont := true
	s := lst.head.next
	for v, nxt := s, s.next; v != &lst.head && cont; v, nxt = nxt, nxt.next {
		cont = f(v, lst)
	}
}
