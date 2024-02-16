package sipcallmon

import (
	"fmt"
	"sync"

	"github.com/intuitivelabs/counters"
)

var pcapStatsLock sync.Mutex
var pcapStats *pcapStatsT

func pcapGlobalStatsInit() (error, *pcapStatsT) {
	ok := true
	pcapStatsLock.Lock()
	{
		if pcapStats == nil {
			pcapStats = &pcapStatsT{}
			ok = pcapStats.Init()
			if !ok {
				pcapStats = nil
			}
		}
	}
	pcapStatsLock.Unlock()
	if !ok {
		return fmt.Errorf("pcap stats: failed to init stats\n"), pcapStats
	}
	return nil, pcapStats
}

type pcapStatsT struct {
	cnts *counters.Group

	hTQueuedMsgs  counters.Handle
	hQueuedMsgs   counters.Handle
	hWrittenMsgs  counters.Handle
	hWrittenBytes counters.Handle
	hAllocMsgs    counters.Handle
	hAllocBytes   counters.Handle

	hDroppedQueue counters.Handle
	hDroppedWr    counters.Handle

	hNewSubdir counters.Handle
	hNewFile   counters.Handle

	hErrMkSubdir counters.Handle
	hErrNewFile  counters.Handle
	hErrNoFile   counters.Handle
	hErrWrHdr    counters.Handle
	hErrWrMsg    counters.Handle
	hErrOther    counters.Handle
	hBUG         counters.Handle
}

func (s *pcapStatsT) Init() bool {
	cntDefs := [...]counters.Def{

		{&s.hTQueuedMsgs, 0, nil, nil, "total_queued_msgs",
			"total number of messages queued for write"},
		{&s.hQueuedMsgs, counters.CntMaxF, nil, nil, "crt_queued_msgs",
			"current number of messages queued for write"},
		{&s.hWrittenMsgs, 0, nil, nil, "written_msgs",
			"total number of messages written to pcap files"},
		{&s.hWrittenBytes, 0, nil, nil, "bytes_written",
			"total bytes written to pcap files"},
		{&s.hAllocMsgs, counters.CntMaxF, nil, nil, "crt_alloc_msgs",
			"currently allocated messages"},
		{&s.hAllocBytes, counters.CntMaxF, nil, nil, "crt_alloc_bytes",
			"currently allocated total size"},

		{&s.hDroppedQueue, 0, nil, nil, "dropped_queue",
			"number of messages dropped due to full write queue"},
		{&s.hDroppedWr, 0, nil, nil, "dropped_write",
			"number of messages dropped due file write errors"},

		{&s.hNewSubdir, 0, nil, nil, "new_subdirs",
			"number of created subdirectories"},
		{&s.hNewFile, 0, nil, nil, "new_files",
			"number of created pcap dump files"},

		{&s.hErrMkSubdir, 0, nil, nil, "err_subdirs",
			"errors creating new subdirectories"},
		{&s.hErrNewFile, 0, nil, nil, "err_new_file",
			"errors creating new files"},
		{&s.hErrNoFile, 0, nil, nil, "err_missing_file",
			"errors opening existing files / append only mode"},
		{&s.hErrWrHdr, 0, nil, nil, "err_wr_header",
			"errors while writing initial pcap file header"},
		{&s.hErrWrMsg, 0, nil, nil, "err_wr_msg",
			"errors while writing a message to pcap file (I/O)"},
		{&s.hErrOther, 0, nil, nil, "err_other",
			"other errors (dbg)"},
		{&s.hBUG, 0, nil, nil, "err_bug",
			"number of detected BUGs (dbg)"},
	}

	entries := len(cntDefs)
	s.cnts = counters.NewGroup("pcap_dump", nil, entries)
	if s.cnts == nil {
		BUG("failed to register counters\n")
		return false
	}
	if !s.cnts.RegisterDefs(cntDefs[:]) {
		BUG("failed to register counters\n")
		return false
	}
	return true
}
