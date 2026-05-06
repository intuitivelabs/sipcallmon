package sipcallmon

// pcapFileUploader manages upload of rotated pcap files.
// Two notification modes (configurable):
//   - channel: renameFile() sends upload requests immediately after rename
//   - watch: fsnotify goroutine watches RotateDir for new files
//
// Upload workers stream files to the upload API using RESTsendStream
// (no in-memory buffering). Each worker has its own RESTclient.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/sys/unix"

	"github.com/intuitivelabs/unsafeconv"
)

// fileUpldTSFromStatx controls how timestamps are derived for files
// without tracker-provided timestamps.
// true: use unix.Statx Btime (birth time, Linux 4.11+).
// false: read the first pcap packet timestamp from the file.
const fileUpldTSFromStatx = true

// FileUpldAction describes what to do with a file after upload.
type FileUpldAction uint8

const (
	FileUpldLeave  FileUpldAction = iota // leave file as-is
	FileUpldDelete                       // os.Remove
	FileUpldMove                         // os.Rename to configured dir
)

// parseFileUpldAction parses a config string into an action.
// "" maps to the given defaultAction.
func parseFileUpldAction(s string, defaultAction FileUpldAction) FileUpldAction {
	switch s {
	case "delete":
		return FileUpldDelete
	case "leave", "keep":
		return FileUpldLeave
	case "":
		return defaultAction
	default:
		// treat as directory path → move
		return FileUpldMove
	}
}

// File upload notification modes.
const (
	FileUpldNotifyChannel = "channel"
	FileUpldNotifyWatch   = "watch"
	FileUpldNotifyBoth    = "both"
)

// pcapFileUpldReq is the message sent from rotation to upload workers.
// Fixed-size struct with inline storage, allocated from a pool.
type pcapFileUpldReq struct {
	upldId   [maxPcapUploadIdLen]byte
	idLen    uint16
	fname    [512]byte
	fnameLen uint16
	fromTS   int64 // unix seconds; 0 = derive from file
	toTS     int64 // unix seconds; 0 = derive from file
}

// pcapFileUpldPool is a mutex-guarded free list of preallocated
// pcapFileUpldReq objects. Faster than sync.Pool for low contention.
type pcapFileUpldPool struct {
	mu   sync.Mutex
	free []*pcapFileUpldReq
}

func (p *pcapFileUpldPool) Init(capacity int) {
	p.free = make([]*pcapFileUpldReq, capacity)
	for i := range p.free {
		p.free[i] = &pcapFileUpldReq{}
	}
}

func (p *pcapFileUpldPool) Get() *pcapFileUpldReq {
	p.mu.Lock()
	n := len(p.free)
	if n == 0 {
		p.mu.Unlock()
		return nil
	}
	req := p.free[n-1]
	p.free = p.free[:n-1]
	p.mu.Unlock()
	return req
}

func (p *pcapFileUpldPool) Put(req *pcapFileUpldReq) {
	p.mu.Lock()
	p.free = append(p.free, req)
	p.mu.Unlock()
}

// pcapFileUploader is the upload worker pool for rotated pcap files.
type pcapFileUploader struct {
	upldCh   chan *pcapFileUpldReq
	pool     pcapFileUpldPool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	nWorkers int
	cfg      *PcapWriterCfg
	stats    *pcapStatsT

	doneAction FileUpldAction
	doneDir    string
	errAction  FileUpldAction
	errDir     string

	// watch mode
	notify     string         // "channel", "watch", "both"
	fmtRegex   *regexp.Regexp // compiled from rotateFmtSegs (nil if watch disabled)
	idCapIdx   int            // regex capture index for %i (-1 if absent)
	baseCapIdx int            // regex capture index for %b (-1 if absent)
}

func (u *pcapFileUploader) Init(cfg *PcapWriterCfg, stats *pcapStatsT) error {
	u.cfg = cfg
	u.stats = stats
	u.nWorkers = cfg.FileUpldWorkers
	u.notify = cfg.FileUpldNotify
	if u.notify == "" {
		u.notify = FileUpldNotifyChannel
	}

	qsize := cfg.FileUpldQueueLen
	if qsize <= 0 {
		qsize = 1000
	}
	u.upldCh = make(chan *pcapFileUpldReq, qsize)
	u.pool.Init(qsize)
	u.stopCh = make(chan struct{})

	// parse post-upload actions
	u.doneAction = parseFileUpldAction(cfg.FileUpldDoneDir, FileUpldDelete)
	if u.doneAction == FileUpldMove {
		u.doneDir = cfg.FileUpldDoneDir
	}
	u.errAction = parseFileUpldAction(cfg.FileUpldErrDir, FileUpldLeave)
	if u.errAction == FileUpldMove {
		u.errDir = cfg.FileUpldErrDir
	}

	// build regex for watch mode and/or startup scan
	watchEnabled := u.notify == FileUpldNotifyWatch ||
		u.notify == FileUpldNotifyBoth
	if watchEnabled || cfg.FileUpldStartupScan {
		u.fmtRegex, u.idCapIdx, u.baseCapIdx = buildRotateFmtRegex(
			cfg.rotateFmtSegs)
		if u.fmtRegex == nil {
			return fmt.Errorf("pcap file uploader: cannot build format regex" +
				" for watch / startup scan")
		}
		if cfg.RotateDir == "" {
			return fmt.Errorf("pcap file uploader: watch / startup scan" +
				" requires pcap_dump_rotate_dir")
		}
	}
	return nil
}

func (u *pcapFileUploader) Start() bool {
	for i := 0; i < u.nWorkers; i++ {
		u.wg.Add(1)
		go u.worker(i)
	}
	// scan rotate dir for leftovers from a previous run
	if u.cfg.FileUpldStartupScan && u.cfg.RotateDir != "" {
		u.scanDir(u.cfg.RotateDir)
	}
	// start watch goroutine if configured
	if u.notify == FileUpldNotifyWatch || u.notify == FileUpldNotifyBoth {
		u.wg.Add(1)
		go u.watchDir()
	}
	return true
}

func (u *pcapFileUploader) Stop() {
	close(u.stopCh)
	u.wg.Wait()
	close(u.upldCh)
}

// UpldCh returns the send-only channel for upload requests.
// Returns nil if channel mode is not active.
func (u *pcapFileUploader) UpldCh() chan<- *pcapFileUpldReq {
	if u.notify == FileUpldNotifyWatch {
		return nil // watch-only mode
	}
	return u.upldCh
}

// Pool returns the upload request pool.
// Returns nil if channel mode is not active.
func (u *pcapFileUploader) Pool() *pcapFileUpldPool {
	if u.notify == FileUpldNotifyWatch {
		return nil
	}
	return &u.pool
}

// worker is the upload worker goroutine.
func (u *pcapFileUploader) worker(id int) {
	defer u.wg.Done()
	client := NewRESTclient(u.cfg.RestCfg)

	for {
		select {
		case req, ok := <-u.upldCh:
			if !ok {
				return
			}
			u.upldFile(req, client)
			u.pool.Put(req)
		case <-u.stopCh:
			// drain remaining
			for {
				select {
				case req, ok := <-u.upldCh:
					if !ok {
						return
					}
					u.upldFile(req, client)
					u.pool.Put(req)
				default:
					return
				}
			}
		}
	}
}

// upldFile streams a rotated pcap file to the upload API.
func (u *pcapFileUploader) upldFile(req *pcapFileUpldReq,
	client *RESTclient) {

	fname := unsafeconv.Str(req.fname[:req.fnameLen])
	upldId := req.upldId[:req.idLen]

	f, err := os.Open(fname)
	if err != nil {
		// file may have been already uploaded/moved/deleted (idempotent)
		if !os.IsNotExist(err) {
			ERR("pcap file uploader: open %q: %v\n", fname, err)
			if u.stats != nil {
				u.stats.cnts.Inc(u.stats.hErrOther)
			}
		}
		return
	}
	fileSize, fromTS, toTS, err := fileUpldInfo(f, req)
	if err != nil {
		f.Close()
		ERR("pcap file uploader: stat %q: %v\n", fname, err)
		if u.stats != nil {
			u.stats.cnts.Inc(u.stats.hErrFileUpldStat)
		}
		return
	}
	if fileSize == 0 {
		f.Close()
		u.onSuccess(fname)
		return
	}

	// build URL
	var urlBuf [512]byte
	uri := buildUpldURL(urlBuf[:0], u.cfg.Upload, upldId, fromTS, toTS)

	status, httpErr := client.RESTsendStream(
		unsafeconv.Str(uri), f, fileSize)
	f.Close()

	if httpErr != nil || status < 200 || status >= 300 {
		if httpErr != nil {
			ERR("pcap file uploader: upload %q: %v\n", fname, httpErr)
		} else {
			ERR("pcap file uploader: upload %q: status %d\n", fname, status)
		}
		if u.stats != nil {
			u.stats.cnts.Inc(u.stats.hErrUpload)
		}
		u.onError(fname)
		return
	}
	if u.stats != nil {
		u.stats.cnts.Inc(u.stats.hUploadedMsgs)
	}
	u.onSuccess(fname)
}

func (u *pcapFileUploader) onSuccess(fname string) {
	switch u.doneAction {
	case FileUpldDelete:
		os.Remove(fname)
	case FileUpldMove:
		moveFile(fname, u.doneDir)
	}
}

func (u *pcapFileUploader) onError(fname string) {
	switch u.errAction {
	case FileUpldDelete:
		os.Remove(fname)
	case FileUpldMove:
		moveFile(fname, u.errDir)
	}
}

// moveFile renames fname into dir, creating dir only if the first
// rename fails because the directory does not exist.
func moveFile(fname, dir string) {
	dst := filepath.Join(dir, filepath.Base(fname))
	err := os.Rename(fname, dst)
	if err != nil && os.IsNotExist(err) {
		os.MkdirAll(dir, 0700)
		err = os.Rename(fname, dst)
	}
	if err != nil {
		ERR("pcap file uploader: move %q -> %q: %v\n", fname, dst, err)
	}
}

// fileUpldInfo returns the file size and resolved timestamps for upload.
// When fileUpldTSFromStatx is true, a single statx syscall on the open fd
// provides size + birth time + mtime (avoids the extra fstat + statx pair).
// When false, falls back to f.Stat() + pcapReadFirstTS.
// req.fromTS/toTS override derived values when non-zero.
// On the pcapReadFirstTS path the file is seeked back to 0.
func fileUpldInfo(f *os.File,
	req *pcapFileUpldReq) (fileSize int64, fromTS, toTS time.Time, err error) {

	if fileUpldTSFromStatx {
		var stx unix.Statx_t
		err = unix.Statx(int(f.Fd()), "",
			unix.AT_EMPTY_PATH,
			unix.STATX_SIZE|unix.STATX_BTIME|unix.STATX_MTIME, &stx)
		if err != nil {
			return
		}
		fileSize = int64(stx.Size)
		toTS = time.Unix(stx.Mtime.Sec, int64(stx.Mtime.Nsec))
		if stx.Mask&unix.STATX_BTIME != 0 {
			fromTS = time.Unix(stx.Btime.Sec, int64(stx.Btime.Nsec))
		} else {
			fromTS = toTS // filesystem doesn't support btime
		}
	} else {
		var fi os.FileInfo
		fi, err = f.Stat()
		if err != nil {
			return
		}
		fileSize = fi.Size()
		toTS = fi.ModTime()
		fromTS = pcapReadFirstTS(f)
		if fromTS.IsZero() {
			fromTS = toTS
		}
		f.Seek(0, io.SeekStart)
	}
	// request-provided timestamps override derived ones
	if req.fromTS != 0 {
		fromTS = time.Unix(req.fromTS, 0)
	}
	if req.toTS != 0 {
		toTS = time.Unix(req.toTS, 0)
	}
	return
}

// pcapReadFirstTS reads the first packet timestamp from a pcap file.
// The pcap global header is 24 bytes; the first record starts at offset 24
// with ts_sec (4 bytes LE) + ts_usec (4 bytes LE).
func pcapReadFirstTS(f *os.File) time.Time {
	var buf [8]byte
	n, err := f.ReadAt(buf[:], 24)
	if err != nil || n < 8 {
		return time.Time{}
	}
	sec := binary.LittleEndian.Uint32(buf[0:4])
	usec := binary.LittleEndian.Uint32(buf[4:8])
	return time.Unix(int64(sec), int64(usec)*1000)
}

// buildUpldURL builds the upload URL into buf (zero-alloc).
// Format: {baseURL}/{upldId}?fromTS={ts}&toTS={ts}
func buildUpldURL(buf []byte, baseURL string, upldId []byte,
	fromTS, toTS time.Time) []byte {

	buf = append(buf, baseURL...)
	if len(buf) > 0 && buf[len(buf)-1] != '/' {
		buf = append(buf, '/')
	}
	buf = append(buf, upldId...)
	buf = append(buf, "?fromTS="...)
	buf = append(buf, url.QueryEscape(fromTS.Format(time.RFC3339))...)
	buf = append(buf, "&toTS="...)
	buf = append(buf, url.QueryEscape(toTS.Format(time.RFC3339))...)
	return buf
}

// --- fsnotify watch mode ---

func (u *pcapFileUploader) watchDir() {
	defer u.wg.Done()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		ERR("pcap file uploader: fsnotify init: %v\n", err)
		return
	}
	defer watcher.Close()

	dir := u.cfg.RotateDir
	if dir == "" {
		ERR("pcap file uploader: watch mode requires pcap_dump_rotate_dir\n")
		return
	}
	// ensure directory exists
	os.MkdirAll(dir, 0700)
	if err := watcher.Add(dir); err != nil {
		ERR("pcap file uploader: watch %q: %v\n", dir, err)
		return
	}

	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			u.handleWatchEvent(ev.Name)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			ERR("pcap file uploader: fsnotify error: %v\n", err)

		case <-u.stopCh:
			return
		}
	}
}

// scanDir scans the rotate directory for existing files and enqueues them.
func (u *pcapFileUploader) scanDir(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		ERR("pcap file uploader: scan %q: %v\n", dir, err)
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(dir, entry.Name())
		u.handleWatchEvent(fullPath)
	}
}

// handleWatchEvent matches a filename against the format regex and
// enqueues an upload request if it matches.
func (u *pcapFileUploader) handleWatchEvent(fullPath string) {
	if u.fmtRegex == nil {
		return
	}
	name := filepath.Base(fullPath)
	match := u.fmtRegex.FindStringSubmatch(name)
	if match == nil {
		return
	}
	upldId := u.extractUpldId(match)
	if len(upldId) == 0 {
		return
	}
	req := u.pool.Get()
	if req == nil {
		// pool exhausted — file stays, will be retried on next event/scan
		if u.stats != nil {
			u.stats.cnts.Inc(u.stats.hFileUpldPoolEmpty)
		}
		return
	}
	req.fnameLen = uint16(copy(req.fname[:], fullPath))
	req.idLen = uint16(copy(req.upldId[:], upldId))
	req.fromTS = 0 // derive from file
	req.toTS = 0
	select {
	case u.upldCh <- req:
	default:
		u.pool.Put(req) // queue full
		WARN("pcap file uploader: upload queue full, skipping %q\n",
			fullPath)
		if u.stats != nil {
			u.stats.cnts.Inc(u.stats.hFileUpldQueueFull)
		}
	}
}

// extractUpldId extracts the upload ID from a regex match.
// If %i was in the format, uses that directly.
// If %b was in the format, strips Prefix/Suffix to recover raw key,
// then computes the upload ID.
func (u *pcapFileUploader) extractUpldId(match []string) []byte {
	// try %i capture first
	if u.idCapIdx > 0 && u.idCapIdx < len(match) && match[u.idCapIdx] != "" {
		return []byte(match[u.idCapIdx])
	}
	// try %b capture: strip prefix/suffix to get raw key
	if u.baseCapIdx > 0 && u.baseCapIdx < len(match) && match[u.baseCapIdx] != "" {
		base := match[u.baseCapIdx]
		key := base
		if len(u.cfg.Prefix) > 0 && len(key) > len(u.cfg.Prefix) {
			key = key[len(u.cfg.Prefix):]
		}
		if len(u.cfg.Suffix) > 0 && len(key) > len(u.cfg.Suffix) {
			// suffix includes extension, strip from end
			sfxNoExt := u.cfg.Suffix
			// find extension start in suffix
			for i := len(sfxNoExt) - 1; i >= 0; i-- {
				if sfxNoExt[i] == '.' {
					sfxNoExt = sfxNoExt[:i]
					break
				}
			}
			if len(sfxNoExt) > 0 && len(key) > len(sfxNoExt) {
				key = key[:len(key)-len(sfxNoExt)]
			}
		}
		// compute upload ID from recovered key
		var idBuf [maxPcapUploadIdLen]byte
		n, err := u.cfg.PcapUploadId(idBuf[:], []byte(key))
		if err != nil {
			return nil
		}
		return idBuf[:n]
	}
	return nil
}

// --- format regex builder ---

// buildRotateFmtRegex compiles the rotateFmtSegs into a regex for matching
// rotated filenames. Returns the regex, capture index for %i, and capture
// index for %b. Returns nil regex if segments are empty.
func buildRotateFmtRegex(segs []pcapRotFmtSeg) (*regexp.Regexp, int, int) {
	if len(segs) == 0 {
		return nil, -1, -1
	}
	var buf []byte
	buf = append(buf, '^')
	capIdx := 0
	idIdx := -1
	baseIdx := -1

	for i := range segs {
		seg := &segs[i]
		switch seg.op {
		case rotFmtLiteral:
			buf = appendRegexQuoted(buf, seg.lit)
		case rotFmtBase:
			capIdx++
			baseIdx = capIdx
			buf = append(buf, "(.+?)"...)
		case rotFmtExt:
			buf = append(buf, `(\.[^./]+)?`...)
			capIdx++
		case rotFmtFull:
			capIdx++
			baseIdx = capIdx
			buf = append(buf, "(.+?)"...)
			buf = append(buf, `(\.[^./]+)?`...)
			capIdx++
		case rotFmtUploadId:
			capIdx++
			idIdx = capIdx
			buf = append(buf, `([A-Za-z0-9_-]+)`...)
		case rotFmtTsSec, rotFmtTsMs, rotFmtTsNs:
			capIdx++
			buf = append(buf, `(\d+)`...)
		case rotFmtTimeLayout:
			capIdx++
			buf = append(buf, `(.+?)`...)
		case rotFmtRand:
			capIdx++
			buf = append(buf, `([0-9a-f]{8})`...)
		case rotFmtSeq:
			capIdx++
			buf = append(buf, `(\d+)`...)
		case rotFmtConflictRand:
			buf = append(buf, `(?:_[0-9a-f]{8})?`...)
		case rotFmtConflictSeq:
			buf = append(buf, `(?:_\d+)?`...)
		case rotFmtConflictRetry:
			buf = append(buf, `(?:_\d+)?`...)
		}
	}
	buf = append(buf, '$')

	re, err := regexp.Compile(string(buf))
	if err != nil {
		ERR("pcap file uploader: bad format regex %q: %v\n", buf, err)
		return nil, -1, -1
	}
	return re, idIdx, baseIdx
}

// appendRegexQuoted appends s with regex metacharacters escaped.
func appendRegexQuoted(buf []byte, s string) []byte {
	const meta = `\.+*?()|[]{}^$`
	for i := 0; i < len(s); i++ {
		c := s[i]
		for j := 0; j < len(meta); j++ {
			if c == meta[j] {
				buf = append(buf, '\\')
				break
			}
		}
		buf = append(buf, c)
	}
	return buf
}
