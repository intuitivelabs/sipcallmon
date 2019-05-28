package sipcallmon

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"

	"andrei/sipsp/bytescase"
	"andrei/sipsp/calltr"
)

type EvFilterOp uint8

const (
	EvFilterNone EvFilterOp = iota
	EvFilterName
	EvFilterSrc
	EvFilterDst
	EvFilterSport
	EvFilterDport
	EvFilterProto
	EvFilterStatus
	EvFilterCallID
	EvFilterFromURI
	EvFilterToURI
	EvFilterMethod
	EvFilterRURI
	EvFilterContact
	EvFilterReason
	EvFilterUA
	EvFilterUAS
	EvFilterLast
)

type evState struct {
	readOnly int
	invalid  bool
}

type EvRing struct {
	lock   sync.Mutex
	evBlst calltr.EventFlags // blacklist for even types
	idx    int
	events []calltr.EventData
	state  []evState // marks in-use events
	newEv  chan struct{}
}

func (er *EvRing) Ignore(events ...calltr.EventType) {
	for _, ev := range events {
		er.evBlst.Set(ev)
	}
}

func (er *EvRing) UnIgnore(events ...calltr.EventType) {
	for _, ev := range events {
		er.evBlst.Clear(ev)
	}
}

func (er *EvRing) ResetBlst() {
	er.evBlst.ResetAll()
}

func (er *EvRing) AddUnsafe(ev *calltr.EventData) bool {
	if len(er.events) == 0 {
		return false
	}
	var i int
	start := er.idx
	for {
		i = er.idx % len(er.events)
		er.state[i].invalid = true
		if er.state[i].readOnly > 0 {
			fmt.Printf("DBG: AddUnsafe: read-only %d idx %d start %d\n", i, er.idx, start)
			er.idx++
			if er.idx-start > len(er.events) {
				fmt.Printf("DBG: AddUnsafe: FAILURE busy %d idx %d start %d\n", i, er.idx, start)
				return false // all busy
			}
			continue
		}
		break
	}
	//  TODO: unlock here
	er.events[i].Reset()
	if er.events[i].Copy(ev) {
		//  TODO: atomic op
		er.state[i].invalid = false
		er.idx++
		return true
	}
	return false
}

func (er *EvRing) Add(ev *calltr.EventData) bool {
	if er.evBlst.Test(ev.Type) {
		return true // no failure, we just ignore it
	}
	er.lock.Lock()
	ret := er.AddUnsafe(ev)
	idx := er.idx
	er.lock.Unlock()
	if er.newEv != nil {
		select {
		case er.newEv <- struct{}{}:
			// do nothing
		default:
			fmt.Fprintf(os.Stderr, "WARNING: send channel full for [%d] %p, skipping signal ...\n", idx, ev)
		}
	}
	return ret
}

// FIXME: overflow error
func (ev *EvRing) Get(pos int) *calltr.EventData {
	i := pos % len(ev.events)
	ev.lock.Lock()
	if pos >= ev.idx || (ev.idx-pos) > len(ev.events) || ev.state[i].invalid {
		ev.lock.Unlock()
		return nil
	}
	ev.state[i].readOnly++
	ev.lock.Unlock()
	return &ev.events[i]
}

func (ev *EvRing) Put(pos int) {
	i := pos % len(ev.events)
	ev.lock.Lock()
	ev.state[i].readOnly--
	ev.lock.Unlock()
	if ev.state[pos%len(ev.events)].readOnly < 0 {
		panic("Put: below 0")
	}
}

func (ev *EvRing) LastIdx() int {
	return ev.idx
}

func (ev *EvRing) BufSize() int {
	return len(ev.events)
}

// Iterate returns the numnber of elements on which it did iterate
func (er *EvRing) Iterate(f func(int, int, *calltr.EventData) bool) int {
	n := 0
	er.lock.Lock()
again:
	start := 0
	if er.idx > len(er.events) {
		start = er.idx - len(er.events)
	}
	for n := start; n < er.idx; n++ {
		p := n % len(er.events)
		if er.state[p].invalid {
			continue // skip
		}

		er.state[p].readOnly++
		er.lock.Unlock()
		n++
		cont := f(n, n-start, &er.events[p])
		er.lock.Lock()
		er.state[p].readOnly--
		if !cont {
			break
		}
		// TODO: start !=0 not needed
		if start != 0 && (er.idx-len(er.events)) > start {
			// wraparround: too much stuff added in the meantime
			// re-init
			fmt.Printf("Iterate: changed e.idx = %d start =%d\n", er.idx, start)
			goto again
		}
	}
	er.lock.Unlock()
	return n
}

var EventsRing EvRing

func (ev *EvRing) Init(no int) {

	ev.events = make([]calltr.EventData, no)
	ev.state = make([]evState, len(ev.events))
	for i := 0; i < len(ev.events); i++ {
		ev.events[i].Init(make([]byte, calltr.EventDataMaxBuf()))
	}
}

func (ev *EvRing) SetEvSignal(ch chan struct{}) {
	ev.newEv = ch
}
func (ev *EvRing) CloseEvSignal() {
	if ev.newEv != nil {
		close(ev.newEv)
		ev.newEv = nil
	}
}

func matchEvent(ed *calltr.EventData, op EvFilterOp, b []byte, re *regexp.Regexp) bool {
	var src []byte

	switch op {
	case EvFilterNone:
		return true // matches always
	case EvFilterName:
		src = []byte(ed.Type.String())
	case EvFilterSrc:
		src = []byte(ed.Src.String())
	case EvFilterDst:
		src = []byte(ed.Dst.String())
	case EvFilterSport:
		src = []byte(strconv.Itoa(int(ed.SPort)))
	case EvFilterDport:
		src = []byte(strconv.Itoa(int(ed.DPort)))
	case EvFilterProto:
		src = []byte(ed.ProtoF.ProtoName())
	case EvFilterStatus:
		src = []byte(strconv.Itoa(int(ed.ReplStatus)))
	case EvFilterCallID:
		src = ed.CallID.Get(ed.Buf)
	default:
		// hack: relaying that the order is the same as for calltr.Attr...
		if op >= EvFilterFromURI && op <= EvFilterUAS {
			src = ed.Attrs[int(op-EvFilterFromURI)].Get(ed.Buf)
		}
	}
	if re != nil {
		return re.Match(src)
	}
	// lower case comparisons TODO: use a direct version
	srclc := make([]byte, len(src))
	bytescase.ToLower(src, srclc)
	blc := make([]byte, len(b))
	bytescase.ToLower(b, blc)
	return bytes.Contains(srclc, blc)
}
