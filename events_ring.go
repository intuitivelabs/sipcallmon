// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"bytes"
	"fmt"
	"net"
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
var cntEvGetHighIdx counters.Handle
var cntEvGetLastIdx counters.Handle
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

// Blacklisted returns true if the corresponding event type is blacklisted.
func (er *EvRing) Blacklisted(ev calltr.EventType) bool {
	return er.evBlst.Test(ev)
}

// acquire an entry for writing.
// On success the acquired entry can be overwritten (it's already reset)
// and the entry _MUST_ be released with releaseEntry() (otherwise it
// would remain makred "busy" forever).
// Returns the entry evring index on success (>=0) and < 0 on error.
func (er *EvRing) acquireEntry() int {
	if len(er.events) == 0 {
		return -1
	}
	var i int
	er.lock.Lock()
	start := er.idx.Get()
	for {
		i = int(er.idx.Get() % EvRingIdx(len(er.events)))
		if er.state[i].readOnly > 0 {
			if DBGon() {
				DBG("read-only %d idx %d start %d\n",
					i, er.idx.Get(), start)
			}
			er.idx.inc()
			er.stats.Inc(cntEvSkipRdOnly)
			er.stats.Inc(cntEvSkipRdOnlyMax)
			if er.idx.Get()-start > EvRingIdx(len(er.events)) {
				if ERRon() {
					ERR("FAILURE busy %d idx %d start %d\n",
						i, er.idx.Get(), start)
				}
				er.lock.Unlock()
				er.stats.Inc(cntEvFailAllRdBusy)
				return -1 // all busy
			}
			continue
		} else {
			er.stats.Set(cntEvSkipRdOnlyMax, 0)
		}
		break
	}
	prevBusy := er.state[i].busy
	if prevBusy {
		// it can happen even if we always increment the counter, if
		// the number of parallel writers + readers >  len(er_event)
		// => give-up, or do the copy under the same lock
		// (but still in the case of a parallel writer the with the
		//  same modulo idx, the entry will be immediately overwritten,
		// the ring size is just to small)
		er.lock.Unlock()
		er.stats.Inc(cntEvFailAllWrBusy)
		return -1
	}
	er.state[i].busy = true
	er.idx.inc() // claim entry
	er.lock.Unlock()

	er.events[i].Reset()
	return i
}

// release an entry previously acquired for writing (by acquireEntry()).
// The parameters are the entry index in the event ring (i) and the
// new entry "valid" state.
func (er *EvRing) releaseEntry(i int, valid bool) {

	er.lock.Lock()
	er.state[i].valid = valid
	er.state[i].busy = false
	er.lock.Unlock()
}

// adds an event to the ring (copy).
// Returns true on success, false on failure.
func (er *EvRing) addSafe(ev *calltr.EventData) bool {
	i := er.acquireEntry()
	if i < 0 {
		return false
	}
	ret := er.events[i].Copy(ev) // MOVE
	er.releaseEntry(i, ret)
	return ret
}

// signalNewEv signals a potential listener that a new event has been added
// to the ring.
func (er *EvRing) signalNewEv() {
	if er.newEv != nil {
		select {
		case er.newEv <- struct{}{}:
			if s := atomic.SwapInt32(&er.skipped, 0); s > 0 {
				idx := er.idx.Get()
				WARN("EvRing.Add recovered after"+
					" skipping %d signals, idx %d\n", s, idx)
			}
			er.stats.Set(cntEvSigsSkippedMax, 0)
			er.stats.Inc(cntEvSigs)
		default:
			if er.skipped == 0 {
				idx := er.idx.Get()
				WARN("EvRing.Add: send channel"+
					" full for [%d], skipping signal\n",
					idx)
			}
			atomic.AddInt32(&er.skipped, 1)
			er.stats.Inc(cntEvSigsSkipped)
			er.stats.Inc(cntEvSigsSkippedMax)
		}
	}
}

// Add adds a new event to the ring, by copying it at the "top" and
// signals a potential registered listener(SetEvSignal(...)).
// It returns true on success and false on failure.
func (er *EvRing) Add(ev *calltr.EventData) bool {
	er.stats.Inc(cntEvMaxParallel)
	er.evStats.Inc(cntEvType[int(ev.Type)])
	if er.Blacklisted(ev.Type) {
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
	er.signalNewEv()
	er.stats.Dec(cntEvMaxParallel)
	return ret
}

// AddBasic adds a new "basic" event to the ring, created from
// the provided source, destination and protocol information + optional
// call-id and reason.
func (er *EvRing) AddBasic(evt calltr.EventType,
	srcIP net.IP, srcPort uint16,
	dstIP net.IP, dstPort uint16,
	proto calltr.NAddrFlags,
	callid []byte, reason []byte,
) bool {
	if er.Blacklisted(evt) {
		er.evStats.Inc(cntEvType[int(evt)])
		er.stats.Inc(cntEvBlst)
		return true // no failure, we just ignore it
	}
	var evd calltr.EventData
	evd.Init(make([]byte, calltr.EventDataMaxBuf()))
	evd.FillBasic(evt, srcIP, srcPort, dstIP, dstPort, proto, callid, reason)
	// TODO: split Add() into AquireEntry() => i; Fill(); ReleaseEntry(i)
	return er.Add(&evd)

}

type GetEvErr uint8

const (
	ErrOk GetEvErr = iota
	ErrOutOfRangeLow
	ErrBusy
	ErrInvalid
	ErrOutOfRangeHigh
	ErrLast
)

// Get returns the entry in the ring at pos on success and nil on error.
// It also returns the next suggested index (useful for retrying after errors)
// and the error reason:
//     - ErrOutOfRangeLow - index out of range, before current ring start.
//                           nxt will be set to crt_idx - ev_buf (ring start)
//     - ErrOutOfRangeHigh - index out of range, after the ring end.
//                           nxt will be set to the ring end (last idx)
//     - ErrLast           - end of elements, index corresponds to the
//                           end of the ring. nxt will be set to the ring end.
//     - ErrBusy - the event entry at pos is currently busy (being written to).
// One could retry it later. nxt is set to pos (retry).
//     - ErrInvalid - the event entry at pos is not valid and should be skipped.// nxt is set to pos + 1.
func (er *EvRing) Get(pos EvRingIdx) (ed *calltr.EventData, nxt EvRingIdx, err GetEvErr) {
	i := int(pos % EvRingIdx(len(er.events)))
	er.lock.Lock()
	lastIdx := er.idx.Get()
	if (lastIdx - pos) > EvRingIdx(len(er.events)) {
		// out-of-range
		er.lock.Unlock()
		if int64(uint64(pos)-uint64(lastIdx)) < 0 {
			// if pos before lastIdx => out of range before start of ring
			er.stats.Inc(cntEvGetOldIdx)
			// return start of ring as next idx + error
			return nil, er.idx.Get() - EvRingIdx(len(er.events)),
				ErrOutOfRangeLow
		} else {
			// if pos after lastIdx => out of range, after end
			er.stats.Inc(cntEvGetHighIdx)
			// return end of ring as next idx + error
			return nil, lastIdx, ErrOutOfRangeHigh
		}
	} else if lastIdx == pos {
		// out-of-range: request for ring last idx
		er.lock.Unlock()
		er.stats.Inc(cntEvGetLastIdx)
		return nil, lastIdx, ErrLast
	} else if er.state[i].busy {
		// NOTE: the else order is important: the check for .busy must
		//       be done before the check for .valid.
		// busy, being written to
		er.lock.Unlock()
		er.stats.Inc(cntEvGetBusyEv)
		return nil, pos, ErrBusy
	} else if !er.state[i].valid {
		// invalid event (e.g. copy failed, initial state)
		er.lock.Unlock()
		er.stats.Inc(cntEvGetInvEv)
		return nil, pos + 1, ErrInvalid
	}
	er.state[i].readOnly++
	er.stats.Inc(cntEvReadOnly2)
	if er.state[i].readOnly == 1 {
		er.stats.Inc(cntEvReadOnly)
	}
	er.lock.Unlock()
	return &er.events[i], pos + 1, ErrOk
}

func (er *EvRing) Put(pos EvRingIdx) {
	i := int(pos % EvRingIdx(len(er.events)))
	er.lock.Lock()
	// TODO: atomic and no lock
	er.state[i].readOnly--
	er.stats.Dec(cntEvReadOnly2)
	if er.state[i].readOnly == 0 {
		er.stats.Dec(cntEvReadOnly)
	}
	er.lock.Unlock()
	if er.state[i].readOnly < 0 {
		Log.PANIC("Put: below 0\n")
	}
}

func (er *EvRing) LastIdx() EvRingIdx {
	return er.idx.Get()
}

func (er *EvRing) BufSize() EvRingIdx {
	return EvRingIdx(len(er.events))
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
			case ErrOutOfRangeLow:
				DBG("Iterate: changed n= %d to %d (e.idx = %d start =%d)\n",
					n, nxtidx, er.LastIdx(), start)
			case ErrInvalid:
				// do nothing , skip over it
			case ErrOutOfRangeHigh:
				DBG("Iterate: out of range high: n= %d -> %d last %d\n",
					n, nxtidx, er.LastIdx())
				fallthrough
			case ErrLast:
				break // or break for (should be equiv.)
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
					DBG("Iterate: changed e.idx = %d start =%d\n",
						er.idx.Get(), start)
					start = er.idx.Get() - EvRingIdx(len(er.events))
					goto restart
				}
			}
			er.lock.Unlock()
	*/
	return cnt
}

func (er *EvRing) Init(no int) {

	er.events = make([]calltr.EventData, no)
	er.state = make([]evState, len(er.events))
	for i := 0; i < len(er.events); i++ {
		er.events[i].Init(make([]byte, calltr.EventDataMaxBuf()))
	}
	ringNo := atomic.AddInt32(&evRingNo, 1) - 1
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
			"blacklisted events based on event type"},
		{&cntEvQueued, 0, nil, nil, "queued",
			"successfully queued/added events"},
		{&cntEvReadOnly, counters.CntMaxF, nil, nil, "read_only",
			"number of temporary read_only entries"},
		{&cntEvReadOnly2, counters.CntMaxF, nil, nil, "read_only2",
			"number of temporary read_only entries"},
		{&cntEvGetOldIdx, 0, nil, nil, "get_old_idx",
			"Get called with a too old index(too slow)"},
		{&cntEvGetHighIdx, 0, nil, nil, "get_high_idx",
			"Get called with an out of range index(too high)"},
		{&cntEvGetLastIdx, 0, nil, nil, "get_last_idx",
			"Get called with the ring end index"},
		{&cntEvGetInvEv, 0, nil, nil, "get_inv_ev",
			"Get index points to an empty/invalid event"},
		{&cntEvGetBusyEv, 0, nil, nil, "get_busy_ev",
			"Get index points to a busy event (parallel write)"},
		{&cntEvMaxParallel, counters.CntMaxF, nil, nil, "parallel",
			"adds that run in parallel (current and max value)"},
	}
	er.stats.Init(fmt.Sprintf("ev_ring%d", ringNo), nil, len(cntDefs))
	if !er.stats.RegisterDefs(cntDefs[:]) {
		Log.PANIC("EvRing.Init: failed to register ev ring counters\n")
	}

	s := len(cntEvType)
	er.evStats.Init("evtype", &er.stats, s)
	for i := 0; i < s; i++ {
		_, ok := er.evStats.RegisterDef(
			&counters.Def{&cntEvType[i], 0, nil, nil,
				calltr.EventType(i).String(), ""})
		if !ok {
			Log.PANIC("EvRing.Init: failed to register counter %d\n", i)
		}
	}
}

func (er *EvRing) SetEvSignal(ch chan struct{}) {
	er.newEv = ch
}
func (er *EvRing) CloseEvSignal() {
	if er.newEv != nil {
		close(er.newEv)
		er.newEv = nil
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
