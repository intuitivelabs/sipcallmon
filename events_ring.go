// // Copyright 2019-2020 Intuitive Labs Gmbh. All rights reserved.
// //
// // Use of this source code is governed by source-available license
// // that can be found in the LICENSE file in the root of the source
// // tree.

package sipcallmon

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/intuitivelabs/bytescase"
	"github.com/intuitivelabs/calltr"
	"github.com/intuitivelabs/counters"
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
	busy     bool
	valid    bool
}

type EvRingIdx uint64

func (i *EvRingIdx) inc() {
	atomic.AddUint64((*uint64)(i), 1)
}

func (i *EvRingIdx) Get() EvRingIdx {
	return EvRingIdx(atomic.LoadUint64((*uint64)(i)))
}

var evRingNo int32

var cntEvSigs counters.Handle
var cntEvSigsSkipped counters.Handle
var cntEvSigsSkippedMax counters.Handle
var cntEvSkipRdOnly counters.Handle
var cntEvSkipRdOnlyMax counters.Handle
var cntEvFail counters.Handle
var cntEvFailAllRdBusy counters.Handle
var cntEvFailAllWrBusy counters.Handle
var cntEvBlst counters.Handle
var cntEvQueued counters.Handle
var cntEvReadOnly counters.Handle
var cntEvReadOnly2 counters.Handle
var cntEvGetOldIdx counters.Handle
var cntEvGetInvEv counters.Handle
var cntEvGetBusyEv counters.Handle
var cntEvMaxParallel counters.Handle

var cntEvType [calltr.EvBad + 1]counters.Handle

type EvRing struct {
	lock    sync.Mutex
	evBlst  calltr.EventFlags // blacklist for event types
	idx     EvRingIdx
	skipped int32 // debugging
	events  []calltr.EventData
	state   []evState // marks in-use events
	newEv   chan struct{}
	stats   counters.Group // general stats
	evStats counters.Group // event type stats
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

func (er *EvRing) addSafe(ev *calltr.EventData) bool {
	if len(er.events) == 0 {
		return false
	}
	var i int
	er.lock.Lock()
	start := er.idx.Get()
	for {
		i = int(er.idx.Get() % EvRingIdx(len(er.events)))
		if er.state[i].readOnly > 0 {
			fmt.Printf("DBG: addSafe: read-only %d idx %d start %d\n",
				i, er.idx.Get(), start)
			er.idx.inc()
			er.stats.Inc(cntEvSkipRdOnly)
			er.stats.Inc(cntEvSkipRdOnlyMax)
			if er.idx.Get()-start > EvRingIdx(len(er.events)) {
				fmt.Printf("DBG: addSafe: FAILURE busy %d idx %d start %d\n",
					i, er.idx.Get(), start)
				er.lock.Unlock()
				er.stats.Inc(cntEvFailAllRdBusy)
				return false // all busy
			}
			continue
		} else {
			er.stats.Set(cntEvSkipRdOnlyMax, 0)
		}
		break
	}
	prev_busy := er.state[i].busy
	if prev_busy {
		// it can happen even if we always increment the counter, if
		// the number of parallel writers + readers >  len(er_event)
		// => give-up, or do the copy under the same lock
		// (but still in the case of a parallel writer the with the
		//  same modulo idx, the entry will be immediately overwritten,
		// the ring size is just to small)
		er.lock.Unlock()
		er.stats.Inc(cntEvFailAllWrBusy)
		return false
	}
	er.state[i].busy = true
	er.idx.inc() // claim entry
	er.lock.Unlock()

	er.events[i].Reset()
	ret := er.events[i].Copy(ev)

	er.lock.Lock()
	er.state[i].valid = ret
	er.state[i].busy = false
	er.lock.Unlock()
	return ret
}

func (er *EvRing) Add(ev *calltr.EventData) bool {
	er.stats.Inc(cntEvMaxParallel)
	er.evStats.Inc(cntEvType[int(ev.Type)])
	if er.evBlst.Test(ev.Type) {
		er.stats.Inc(cntEvBlst)
		er.stats.Dec(cntEvMaxParallel)
		return true // no failure, we just ignore it
	}
	ret := er.addSafe(ev)
	if !ret {
		er.stats.Inc(cntEvFail)
		er.stats.Dec(cntEvMaxParallel)
		return ret
	}

	er.stats.Inc(cntEvQueued)
	idx := er.idx.Get()
	if er.newEv != nil {
		select {
		case er.newEv <- struct{}{}:
			if s := atomic.SwapInt32(&er.skipped, 0); s > 0 {
				fmt.Fprintf(os.Stderr, "WARNING: EvRing.Add recovered after"+
					" skipping %d signals, idx %d\n", s, idx)
			}
			er.stats.Set(cntEvSigsSkippedMax, 0)
			er.stats.Inc(cntEvSigs)
		default:
			if er.skipped == 0 {
				fmt.Fprintf(os.Stderr, "WARNING: EvRing.Add: send channel"+
					" full for [%d] %p, skipping signal\n",
					idx, ev)
			}
			atomic.AddInt32(&er.skipped, 1)
			er.stats.Inc(cntEvSigsSkipped)
			er.stats.Inc(cntEvSigsSkippedMax)
		}
	}
	er.stats.Dec(cntEvMaxParallel)
	return ret
}

type GetEvErr uint8

const (
	ErrOk GetEvErr = iota
	ErrOutOfRange
	ErrBusy
	ErrInvalid
)

// Get returns the entry in the ring at pos on success and nil on error.
// It also returns the next suggested index (useful for retrying after errors)
// and the error reason:
//    - ErrOutOfRange - index out of range, nxt will be set to crt_idx - ev_buf
// size
//     - ErrBusy - the event entry at pos is currently busy (being written to).
// One could retry it later. nxt is set to pos (retry).
//     - ErrInvalid - the event entry at pos is not valid and should be skipped.// nxt is set to pos + 1.
func (ev *EvRing) Get(pos EvRingIdx) (ed *calltr.EventData, nxt EvRingIdx, err GetEvErr) {
	i := int(pos % EvRingIdx(len(ev.events)))
	ev.lock.Lock()
	if (ev.idx.Get() - pos) > EvRingIdx(len(ev.events)) {
		// out-of-range
		ev.lock.Unlock()
		ev.stats.Inc(cntEvGetOldIdx)
		return nil, ev.idx.Get() - EvRingIdx(len(ev.events)), ErrOutOfRange
	} else if !ev.state[i].valid {
		// invalid event (e.g. copy failed, initial state)
		ev.lock.Unlock()
		ev.stats.Inc(cntEvGetInvEv)
		return nil, pos + 1, ErrInvalid
	} else if ev.state[i].busy {
		// busy, being written to
		ev.lock.Unlock()
		ev.stats.Inc(cntEvGetBusyEv)
		return nil, pos, ErrBusy
	}
	ev.state[i].readOnly++
	ev.stats.Inc(cntEvReadOnly2)
	if ev.state[i].readOnly == 1 {
		ev.stats.Inc(cntEvReadOnly)
	}
	ev.lock.Unlock()
	return &ev.events[i], pos + 1, ErrOk
}

func (ev *EvRing) Put(pos EvRingIdx) {
	i := int(pos % EvRingIdx(len(ev.events)))
	ev.lock.Lock()
	// TODO: atomic and no lock
	ev.state[i].readOnly--
	ev.stats.Dec(cntEvReadOnly2)
	if ev.state[i].readOnly == 0 {
		ev.stats.Dec(cntEvReadOnly)
	}
	ev.lock.Unlock()
	if ev.state[i].readOnly < 0 {
		panic("Put: below 0")
	}
}

func (ev *EvRing) LastIdx() EvRingIdx {
	return ev.idx.Get()
}

func (ev *EvRing) BufSize() EvRingIdx {
	return EvRingIdx(len(ev.events))
}

// IterateCbk is the type for the function callback for the Iterate
// function.
// crt is the current event number/idx, rel is the event number relative
// to the starting iterate position, d is the eventdata and arg is the
//  callback argumnet passed to Iterate().
// It should return true to continue the iteration or false to stop it.
type IterateCbk func(crt, rel EvRingIdx, d *calltr.EventData, arg interface{}) bool

// Iterate returns the number of valid elements on which it did iterate.
// pos is the starting event number, f is the callback function and
// cbkArg is an argument that will be passed to the callback function.
func (er *EvRing) Iterate(pos EvRingIdx, f IterateCbk, cbkArg interface{}) int {
	var cnt int
	start := pos
	if er.LastIdx()-start > EvRingIdx(len(er.events)) {
		if start > er.LastIdx() {
			// FIXME: not overflow safe, is idx overflows entries will
			//        might be  skipped, if diff to high
			return 0
		}
		// start point outside the current range, adjust it upwards
		start = er.LastIdx() - EvRingIdx(len(er.events))
	}

	for n := start; n != er.LastIdx(); {
		if ed, nxtidx, err := er.Get(n); ed != nil {
			cnt++
			cont := f(n, n%EvRingIdx(len(er.events)), ed, cbkArg)
			er.Put(n)
			n = nxtidx
			if !cont {
				break
			}
		} else {
			switch err {
			case ErrBusy:
				// we don't want to spin wait on it, we'll just skip it
				n++
				continue
			case ErrOutOfRange:
				fmt.Printf("Iterate: changed n= %d to %d (e.idx = %d start =%d)\n",
					n, nxtidx, er.LastIdx(), start)
			case ErrInvalid:
				// do nothing , skip over it
			}
			n = nxtidx
		}
	}

	/*
				er.lock.Lock()
		restart:
			for n := start; n != er.idx.Get(); n++ {
				p := int(n % EvRingIdx(len(er.events)))
				if !er.state[p].valid {
					continue // skip
				}
				if er.state[p].busy {
					// we could spin, waiting, but in this case we'll just skip it
					continue // skip
				}

				er.state[p].readOnly++
				if er.state[p].readOnly == 1 {
					er.stats.Inc(cntEvReadOnly)
				}
				er.lock.Unlock()
				cnt++
				cont := f(n, EvRingIdx(p), &er.events[p], cbkArg)
				er.lock.Lock()
				er.state[p].readOnly--
				if er.state[p].readOnly == 0 {
					er.stats.Dec(cntEvReadOnly)
				}
				if !cont {
					break
				}
				if (er.idx.Get() - start) > EvRingIdx(len(er.events)) {
					// wraparround: too much stuff added in the meantime
					// re-init
					fmt.Printf("Iterate: changed e.idx = %d start =%d\n",
						er.idx.Get(), start)
					start = er.idx.Get() - EvRingIdx(len(er.events))
					goto restart
				}
			}
			er.lock.Unlock()
	*/
	return cnt
}

var EventsRing EvRing

func (ev *EvRing) Init(no int) {

	ev.events = make([]calltr.EventData, no)
	ev.state = make([]evState, len(ev.events))
	for i := 0; i < len(ev.events); i++ {
		ev.events[i].Init(make([]byte, calltr.EventDataMaxBuf()))
	}
	ring_no := atomic.AddInt32(&evRingNo, 1) - 1
	cntDefs := [...]counters.Def{
		{&cntEvSigs, 0, nil, nil, "signals",
			"sent event signals"},
		{&cntEvSigsSkipped, 0, nil, nil, "skipped_sigs",
			"skipped signals, slow consumer"},
		{&cntEvSigsSkippedMax, counters.CntMaxF | counters.CntHideVal,
			nil, nil, "skipped_sigs_max",
			"skipped signals, slow consumer"},
		{&cntEvSkipRdOnly, 0, nil, nil, "skip_rdonly",
			"skipped entries due to active reader"},
		{&cntEvSkipRdOnlyMax, counters.CntMaxF | counters.CntHideVal,
			nil, nil, "skip_rdonly_max",
			"skipped entries due to active reader"},
		{&cntEvFail, 0, nil, nil, "fail",
			"failed add event operation - copy failed or all entries busy"},
		{&cntEvFailAllRdBusy, 0, nil, nil, "rd_busy",
			"failed add event operation - all entries are read-busy"},
		{&cntEvFailAllWrBusy, 0, nil, nil, "wr_busy",
			"failed add event operation - all entries are write-busy: event ring too small"},
		{&cntEvBlst, 0, nil, nil, "blst",
			"blacklisted events"},
		{&cntEvQueued, 0, nil, nil, "queued",
			"successfully queued/added events"},
		{&cntEvReadOnly, counters.CntMaxF, nil, nil, "read_only",
			"number of temporary read_only entries"},
		{&cntEvReadOnly2, counters.CntMaxF, nil, nil, "read_only2",
			"number of temporary read_only entries"},
		{&cntEvGetOldIdx, 0, nil, nil, "get_old_idx",
			"Get called with a too old index(too slow)"},
		{&cntEvGetInvEv, 0, nil, nil, "get_inv_ev",
			"Get index points to an empty/invalid event"},
		{&cntEvGetBusyEv, 0, nil, nil, "get_busy_ev",
			"Get index points to a busy event (parallel write)"},
		{&cntEvMaxParallel, counters.CntMaxF, nil, nil, "parallel",
			"adds that run in parallel (current and max value)"},
	}
	ev.stats.Init(fmt.Sprintf("ev_ring%d", ring_no), nil, len(cntDefs))
	if !ev.stats.RegisterDefs(cntDefs[:]) {
		panic("failed to register ev ring counters")
	}

	s := len(cntEvType)
	ev.evStats.Init("evtype", &ev.stats, s)
	for i := 0; i < s; i++ {
		_, ok := ev.evStats.RegisterDef(
			&counters.Def{&cntEvType[i], 0, nil, nil,
				calltr.EventType(i).String(), ""})
		if !ok {
			panic(fmt.Sprintf("failed to register counter %d", i))
		}
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
