package sipcallmon

import (
	"sync"
	"sync/atomic"
)

type AcmeIPFIXconnLst struct {
	head AcmeIPFIXconn // used only as list head

	connsNo atomic.Uint32
	lock    sync.Mutex
}

// Init initialises a list head
func (lst *AcmeIPFIXconnLst) Init() {
	lst.head.next = &lst.head
	lst.head.prev = &lst.head
	lst.connsNo.Store(0)
}

func (lst *AcmeIPFIXconnLst) IsInit() bool {
	return lst.head.next != nil && lst.head.prev != nil
}

func (lst *AcmeIPFIXconnLst) Lock() {
	lst.lock.Lock()
}

func (lst *AcmeIPFIXconnLst) Unlock() {
	lst.lock.Unlock()
}

func (lst *AcmeIPFIXconnLst) InsertUnsafe(e *AcmeIPFIXconn) uint32 {
	e.prev = &lst.head
	e.next = lst.head.next
	e.next.prev = e
	lst.head.next = e
	return lst.connsNo.Add(1)
}

func (lst *AcmeIPFIXconnLst) RmUnsafe(e *AcmeIPFIXconn) uint32 {
	e.prev.next = e.next
	e.next.prev = e.prev
	// "mark" e as detached
	e.next = e
	e.prev = e
	return lst.connsNo.Add(^(uint32(0))) // Dec
}

func (lst *AcmeIPFIXconnLst) ConnsNo() uint32 {
	return lst.connsNo.Load()
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

// GetConnInfo will fill an AcmeIPFIXconnInfo array from the
// list of the connections, starting at connection with index
// equal to start and ending after copying "no" connections or when
// the array is full.
// It returns the number of filled elements in the array and the
// total number of connections in the list (ConnsNo()).
func (lst *AcmeIPFIXconnLst) GetConnInfo(info []AcmeIPFIXconnInfo,
	start int, no int) (int, int) {
	var i int
	var connsNo uint32

	if start < 0 || no <= 0 {
		return 0, int(lst.connsNo.Load())
	}
	lst.Lock()
	{
		lst.ForEachUnsafe(func(c *AcmeIPFIXconn) bool {
			if i < start {
				i++
				return true
			}
			if (i - start) >= no {
				return false // stop, exceeded requested number
			}
			if (i - start) < len(info) {
				c.GetInfo(&info[i-start])
			} else {
				return false // stop, no more space in info
			}
			i++
			return true
		})

		connsNo = lst.connsNo.Load()
	}
	lst.Unlock()
	if i < start {
		return 0, int(connsNo)
	}
	return i - start, int(connsNo)
}
