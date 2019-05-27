package sipcallmon

import (
	"bytes"
	"fmt"
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

type evring struct {
	lock   sync.Mutex
	evBlst calltr.EventFlags // blacklist for even types
	idx    int
	events []calltr.EventData
	busy   []bool // marks in-use events
}

func (er *evring) Ignore(events ...calltr.EventType) {
	for _, ev := range events {
		er.evBlst.Set(ev)
	}
}

func (er *evring) UnIgnore(events ...calltr.EventType) {
	for _, ev := range events {
		er.evBlst.Clear(ev)
	}
}

func (er *evring) ResetBlst() {
	er.evBlst.ResetAll()
}

func (er *evring) AddUnsafe(ev *calltr.EventData) bool {
	if len(er.events) == 0 {
		return false
	}
	var i int
	start := er.idx
	for {
		i = er.idx % len(er.events)
		if er.busy[i] {
			fmt.Printf("AddUnsafe: busy %d idx %d start %d\n", i, er.idx, start)
			er.idx++
			if er.idx-start > len(er.events) {
				fmt.Printf("AddUnsafe: FAILURE busy %d idx %d start %d\n", i, er.idx, start)
				return false // all busy
			}
			continue
		}
		break
	}
	er.events[i].Reset()
	if er.events[i].Copy(ev) {
		er.idx++
		return true
	}
	return false
}

func (er *evring) Add(ev *calltr.EventData) bool {
	if er.evBlst.Test(ev.Type) {
		return true // no failure, we just ignore it
	}
	er.lock.Lock()
	defer er.lock.Unlock()
	return er.AddUnsafe(ev)
}

func (er *evring) Iterate(f func(int, int, *calltr.EventData) bool) {
	er.lock.Lock()
again:
	start := 0
	if er.idx > len(er.events) {
		start = er.idx - len(er.events)
	}
	for i := start; i < er.idx; i++ {
		er.busy[i%len(er.events)] = true
		er.lock.Unlock()
		cont := f(i, i-start, &er.events[i%len(er.events)])
		er.lock.Lock()
		er.busy[i%len(er.events)] = false
		if !cont {
			break
		}
		if start != 0 && (er.idx-len(er.events)) > start {
			// more stuff added in the meantime
			// re-init
			fmt.Printf("Iterate: changed e.idx = %d start =%d\n", er.idx, start)
			goto again
		}
	}
	er.lock.Unlock()
}

var eventsRing evring

func init() {

	eventsRing.events = make([]calltr.EventData, 102400)
	eventsRing.busy = make([]bool, len(eventsRing.events))
	for i := 0; i < len(eventsRing.events); i++ {
		eventsRing.events[i].Init(make([]byte, calltr.EventDataMaxBuf()))
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
