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
			stats := &pcapStatsT{}
			ok = stats.Init()
			if ok {
				pcapStats = stats
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

	hTQueuedMsgs   counters.Handle
	hQueuedMsgs    counters.Handle
	hWrittenMsgs   counters.Handle
	hWrittenBytes  counters.Handle
	hUploadedMsgs  counters.Handle
	hUploadedBytes counters.Handle
	hAllocMsgs     counters.Handle
	hAllocBytes    counters.Handle
	hAllocHits     counters.Handle

	hDroppedQueue counters.Handle
	hDroppedWr    counters.Handle

	hMaxMsgsWorker counters.Handle
	hMinMsgsWorker counters.Handle
	hAvgMsgsWorker counters.Handle

	hNewSubdir      counters.Handle
	hNewFile        counters.Handle
	hFileExists     counters.Handle
	hNewMissingFile counters.Handle
	hNewUpldFhdr    counters.Handle

	hErrMkSubdir   counters.Handle
	hErrNewFile    counters.Handle
	hErrAppendOnly counters.Handle
	hErrWrHdr      counters.Handle
	hErrWrMsg      counters.Handle
	hErrUpload     counters.Handle
	hRejUpload     counters.Handle
	hErrFdLimit    counters.Handle
	hErrOther      counters.Handle
	hBUG           counters.Handle

	hFdTrackHits       counters.Handle
	hFdTrackMisses     counters.Handle
	hFdTrackEntries    counters.Handle
	hFdTrackRotations  counters.Handle
	hFdTrackRenames    counters.Handle
	hFdTrackHeapAlloc  counters.Handle
	hFdTrackHeapFree   counters.Handle
	hFdTrackLimitEx    counters.Handle
	hErrFdTrackRename  counters.Handle
}

func (s *pcapStatsT) Init() bool {
	cntDefs := [...]counters.Def{

		{&s.hTQueuedMsgs, 0, nil, nil, "total_queued_msgs",
			"total number of messages queued for write"},
		{&s.hQueuedMsgs, counters.CntNonMonoF | counters.CntMaxF,
			nil, nil, "crt_queued_msgs",
			"current number of messages queued for write"},
		{&s.hWrittenMsgs, 0, nil, nil, "written_msgs",
			"total number of messages written to pcap files"},
		{&s.hWrittenBytes, 0, nil, nil, "bytes_written",
			"total bytes written to pcap files"},
		{&s.hUploadedMsgs, 0, nil, nil, "uploaded_msgs",
			"total number of messages uploaded over http"},
		{&s.hUploadedBytes, 0, nil, nil, "bytes_uploaded",
			"total bytes uploaded over http"},
		{&s.hAllocMsgs, counters.CntNonMonoF | counters.CntMaxF,
			nil, nil, "crt_alloc_msgs",
			"currently allocated messages"},
		{&s.hAllocBytes, counters.CntNonMonoF | counters.CntMaxF,
			nil, nil, "crt_alloc_bytes",
			"currently allocated total size"},
		{&s.hAllocHits, counters.CntNonMonoF,
			nil, nil, "alloc_pool_hits",
			"allocs cached in the pool"},

		{&s.hDroppedQueue, 0, nil, nil, "dropped_queue",
			"number of messages dropped due to full write queue"},
		{&s.hDroppedWr, 0, nil, nil, "dropped_write",
			"number of messages dropped due to file or network write errors"},

		{&s.hMaxMsgsWorker, counters.CntNonMonoF,
			nil, nil, "max_msgs_wrk",
			"maximum number of messages handled by a worker"},
		{&s.hMinMsgsWorker, counters.CntNonMonoF,
			minMsgsWorker, &pcapDumper, "min_msgs_wrk",
			"minimum number of messages handled by a worker"},
		{&s.hAvgMsgsWorker, counters.CntNonMonoF,
			avgMsgsWorker, &pcapDumper, "avg_msgs_wrk",
			"average messages handled by a worker (rounded down to int)"},

		{&s.hNewSubdir, 0, nil, nil, "new_subdirs",
			"number of created subdirectories"},
		{&s.hNewFile, 0, nil, nil, "new_files",
			"number of created pcap dump files"},
		{&s.hFileExists, 0, nil, nil, "file_already_exists",
			"number of create file attempts for which the file already exists"},
		{&s.hNewMissingFile, 0, nil, nil, "new_missing_files",
			"number of created pcap dump files when the target file is missing"},
		{&s.hNewUpldFhdr, 0, nil, nil, "new_uploaded_files",
			"number of uploaded start of file pcap headers"},

		{&s.hErrMkSubdir, 0, nil, nil, "err_subdirs",
			"errors creating new subdirectories"},
		{&s.hErrNewFile, 0, nil, nil, "err_new_file",
			"errors creating new files"},
		{&s.hErrAppendOnly, 0, nil, nil, "err_append_only",
			"errors appending to existing files in append only mode"},
		{&s.hErrWrHdr, 0, nil, nil, "err_wr_header",
			"errors while writing initial pcap file header"},
		{&s.hErrWrMsg, 0, nil, nil, "err_wr_msg",
			"errors while writing a message to pcap file (I/O)"},
		{&s.hErrUpload, 0, nil, nil, "err_upload",
			"errors (network) while uploading messages"},
		{&s.hRejUpload, 0, nil, nil, "rejected_upload",
			"rejected message upload attempts"},
		{&s.hErrFdLimit, 0, nil, nil, "err_fd_limit",
			"os.OpenFile failed with EMFILE or ENFILE (fd limit exceeded)"},
		{&s.hErrOther, 0, nil, nil, "err_other",
			"other errors (dbg)"},
		{&s.hBUG, 0, nil, nil, "err_bug",
			"number of detected BUGs (dbg)"},

		{&s.hFdTrackHits, 0, nil, nil, "fd_track_hits",
			"fd tracker hash table hits (cached fd reused)"},
		{&s.hFdTrackMisses, 0, nil, nil, "fd_track_misses",
			"fd tracker hash table misses (new fd opened)"},
		{&s.hFdTrackEntries, counters.CntNonMonoF | counters.CntMaxF,
			nil, nil, "fd_track_entries",
			"current number of tracked open file descriptors"},
		{&s.hFdTrackRotations, 0, nil, nil, "fd_track_rotations",
			"fd tracker entries rotated by timer"},
		{&s.hFdTrackRenames, 0, nil, nil, "fd_track_renames",
			"successful file renames on fd tracker eviction"},
		{&s.hFdTrackHeapAlloc, 0, nil, nil, "fd_track_heap_alloc",
			"fd tracker entries allocated outside pre-alloc pool"},
		{&s.hFdTrackHeapFree, 0, nil, nil, "fd_track_heap_free",
			"fd tracker heap entries freed (not returned to free list)"},
		{&s.hFdTrackLimitEx, 0, nil, nil, "fd_track_limit_exceeded",
			"fd tracker add rejected due to global open fd limit"},
		{&s.hErrFdTrackRename, 0, nil, nil, "err_fd_track_rename",
			"errors renaming files on fd tracker eviction"},
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

func minMsgsWorker(g *counters.Group, h counters.Handle, v counters.Val,
	p interface{}) counters.Val {
	pcapWriter := p.(*PcapWriter)
	if pcapWriter != nil {
		return counters.Val(pcapWriter.MinMsgWorker())
	}
	return counters.Val(0)
}

func avgMsgsWorker(g *counters.Group, h counters.Handle, v counters.Val,
	p interface{}) counters.Val {
	tmsgs := g.Get(pcapStats.hTQueuedMsgs)
	pcapWriter := p.(*PcapWriter)
	if pcapWriter != nil {
		workers := pcapWriter.WorkersNo()
		if workers > 0 {
			return tmsgs / counters.Val(workers)
		}
	}
	return counters.Val(0)
}
