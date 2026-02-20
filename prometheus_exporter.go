// Copyright 2026 Frafos GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/intuitivelabs/counters"
	"github.com/intuitivelabs/unsafeconv"
)

// promMetricsBufPool is a buffer pool for Prometheus metrics export
var promMetricsBufPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 8192))
	},
}

func getPromBuffer() *bytes.Buffer {
	return promMetricsBufPool.Get().(*bytes.Buffer)
}

func putPromBuffer(buf *bytes.Buffer) {
	buf.Reset()
	promMetricsBufPool.Put(buf)
}

// prometheusMetricName converts a counter name to prometheus format
// using the provided buffer for zero-allocation string conversion.
// Each call appends to the buffer, ensuring returned strings don't overlap.
// The returned string shares memory with buf and buf must not be modified
// while the string is in use.
// WARNING: if buf is not large enough it will be reallocated. The previously
// returned strings (if any) remain valid, pointing into the old buf (and
// keeping the old buf from being freed)
func prometheusMetricName(name string, buf *[]byte) string {
	if len(name) == 0 {
		return name
	}

	// first pass: check if modification is needed
	firstChar := name[0]
	needsMod := !((firstChar >= 'A' && firstChar <= 'Z') || (firstChar >= 'a' && firstChar <= 'z') || firstChar == '_')

	if !needsMod {
		for i := 1; i < len(name); i++ {
			c := name[i]
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == ':') {
				needsMod = true
				break
			}
		}
	}

	// if no modification needed, return original
	if !needsMod {
		return name
	}

	// ensure buffer has enough capacity
	needed := len(*buf) + len(name)
	if needed > cap(*buf) {
		// Grow buffer
		newCap := max(cap(*buf)*2, needed, 256)
		newBuf := make([]byte, len(*buf), newCap)
		// the copy below is not really needed, since previous strings would
		// point into the old buffer (keeping it alive). It even wastes some
		// bytes (since nobody looks into buf), but makes it "nicer"
		copy(newBuf, *buf)
		*buf = newBuf
	}

	// Allocate space from end of buffer
	start := len(*buf)
	*buf = (*buf)[:start+len(name)]
	dst := (*buf)[start:]

	for i := 0; i < len(name); i++ {
		c := name[i]
		valid := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
		if i > 0 {
			valid = valid || (c >= '0' && c <= '9') || c == ':'
		}
		if valid {
			dst[i] = c
		} else {
			dst[i] = '_'
		}
	}

	return unsafeconv.Str(dst)
}

// prometheusExportCounter exports a single counter in prometheus format
// w is the writer for output
// g is the counter group
// c is the counter handle
// fullName is the complete metric name (prefix + counter name)
// buf is the output buffer
// prFlags controls what to export (reserved for future use)
func prometheusExportCounter(w io.Writer, g *counters.Group,
	c counters.Handle, fullName string, buf *bytes.Buffer, prFlags uint32) {
	// nameBuf is used for zero-allocation metric name conversion
	var tmpBuf [256]byte
	nameBuf := tmpBuf[0:0]

	if len(fullName) == 0 {
		return
	}

	flags := g.GetFlags(c)
	metricName := prometheusMetricName(fullName, &nameBuf)

	// Skip hidden counters
	if flags&counters.CntHideAllF != 0 {
		return
	}

	// Get counter value
	val := g.Get(c)

	// Skip zero values if hide zero flag is set
	if val == 0 &&
		(flags&counters.CntHideZeroF != 0 || prFlags&counters.PrHideZero != 0) {
		return
	}

	// Determine metric type
	metricType := "counter"
	// declare non-monotonic counters as prometheus gauges
	if flags&(counters.CntNonMonoF|counters.CntMinF|counters.CntMaxF) != 0 {
		metricType = "gauge"
	}

	// Write TYPE annotation
	buf.WriteString("# TYPE ")
	buf.WriteString(metricName)
	buf.WriteByte(' ')
	buf.WriteString(metricType)
	buf.WriteByte('\n')

	if prFlags&counters.PrDesc != 0 {
		// Write HELP annotation if description exists
		desc := g.GetDesc(c)
		if len(desc) > 0 {
			buf.WriteString("# HELP ")
			buf.WriteString(metricName)
			buf.WriteByte(' ')
			buf.WriteString(desc)
			buf.WriteByte('\n')
		}
	}

	// Write metric value - use strconv for efficient integer conversion
	buf.WriteString(metricName)
	buf.WriteByte(' ')
	buf.Write(strconv.AppendUint(nil, uint64(val), 10))
	buf.WriteByte('\n')

	// Export min value if present
	if flags&counters.CntMinF != 0 {
		minVal := g.GetMin(c)
		if minVal != counters.Val(^uint64(0)) {
			buf.WriteString("# TYPE ")
			buf.WriteString(metricName)
			buf.WriteString("_min gauge\n")
			buf.WriteString(metricName)
			buf.WriteString("_min ")
			buf.Write(strconv.AppendUint(nil, uint64(minVal), 10))
			buf.WriteByte('\n')
		}
	}

	// Export max value if present
	if flags&counters.CntMaxF != 0 {
		maxVal := g.GetMax(c)
		buf.WriteString("# TYPE ")
		buf.WriteString(metricName)
		buf.WriteString("_max gauge\n")
		buf.WriteString(metricName)
		buf.WriteString("_max ")
		buf.Write(strconv.AppendUint(nil, uint64(maxVal), 10))
		buf.WriteByte('\n')
	}

	// Flush buffer periodically to avoid excessive memory usage
	if buf.Len() >= 4096 {
		w.Write(buf.Bytes())
		buf.Reset()
	}
}

// prometheusExportGroup exports counters from a group and its subgroups
//
//	in prometheus format
//
// Uses buffers to minimize write calls and allocations.
// If buf is nil, a new buffer is obtained from the pool.
// nameBuf is used for zero-allocation metric name conversion.
func prometheusExportGroup(w io.Writer, g *counters.Group, prefix string,
	buf *bytes.Buffer, prFlags uint32) {
	// use a buffer for batch writes
	ownBuffer := false
	if buf == nil {
		buf = getPromBuffer()
		defer putPromBuffer(buf)
		ownBuffer = true
	}

	// export counters in this group
	cntNo := g.CntNo()
	for i := 0; i < cntNo; i++ {
		h := counters.Handle(i)
		// build full name and export counter
		name := g.GetName(h)
		if len(name) == 0 {
			continue
		}
		fullName := prefix + name
		prometheusExportCounter(w, g, h, fullName, buf, prFlags)
	}

	// recursively export subgroups
	if prFlags&counters.PrRec != 0 {
		n := g.GetSubGroupsNo()
		if n > 0 {
			subgroups := make([]*counters.Group, 0, n)
			g.GetSubGroups(&subgroups)
			for _, sg := range subgroups {
				if sg != nil {
					newPrefix := prefix + sg.Name + "_"
					// reuse the same buffers
					prometheusExportGroup(w, sg, newPrefix, buf, prFlags)
				}
			}
		}
	}

	// write any remaining data only if we own the buffer (top-level call)
	if ownBuffer && buf.Len() > 0 {
		w.Write(buf.Bytes())
	}
}

// httpPrometheusMetrics exports counters in prometheus text format
// Optimized for minimal allocations and efficient writes
func httpPrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	// Set content type for Prometheus
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var prFlags uint32 //"print" flags

	// get buffers for efficient writes and zero-allocation string conversion
	buf := getPromBuffer()
	defer putPromBuffer(buf)

	// get parameters
	query := r.URL.Query()
	groups := query["group"]
	cntrs := query["counter"]
	_, nonzero := query["nonzero"]
	if !nonzero {
		_, nonzero = query["nz"]
	}
	short := false
	if _, hasShort := query["short"]; hasShort {
		s := r.FormValue("short")
		if len(s) > 0 {
			if v, err := strconv.ParseBool(s); err == nil {
				short = v
			} else {
				buf.WriteString("# ERROR: bad parameter value: short= ")
				buf.WriteString(strconv.Quote(s))
				buf.WriteString(" :")
				buf.WriteString(strconv.Quote(err.Error()))
				buf.WriteByte('\n')
			}
		} else {
			// short present but with no value => true
			short = true
		}
	}
	flgs := r.FormValue("flags")
	if len(flgs) > 0 {
		if v, err := strconv.ParseUint(flgs, 10, 8); err == nil {
			// numeric format
			prFlags = uint32(v)
		} else if v, err := strconv.ParseUint(flgs, 16, 8); err == nil {
			// hex format
			prFlags = uint32(v)
		} else {
			// string: flags names separated by "|"
			fvals := map[string]int{
				"fullname": counters.PrFullName,
				"val":      counters.PrVal,
				"desc":     counters.PrDesc,
				"rec":      counters.PrRec,
				"nz":       counters.PrHideZero,
				"nonzero":  counters.PrHideZero,
			}
			for _, f := range strings.Split(flgs, "|") {
				if v, ok := fvals[f]; ok {
					prFlags |= uint32(v)
				} else {
					buf.WriteString("# ERROR: bad flag ")
					buf.WriteString(f)
					buf.WriteString(" in parameter flags=")
					buf.WriteString(strconv.Quote(flgs))
					buf.WriteByte('\n')
				}
			}
		}
	} else {
		prFlags = counters.PrFullName | counters.PrVal | counters.PrRec
		if !short {
			prFlags |= counters.PrDesc
		}
	}

	if nonzero {
		prFlags |= counters.PrHideZero
	}

	// export uptime as a gauge
	buf.WriteString("# TYPE uptime_seconds gauge\n")
	buf.WriteString("# HELP uptime_seconds Time since the server started\n")
	buf.WriteString("uptime_seconds ")
	// convert duration to seconds
	secs := int64(time.Since(StartTS).Seconds())
	buf.Write(strconv.AppendUint(nil, uint64(secs), 10))
	buf.WriteByte('\n')
	buf.WriteByte('\n')

	if len(groups) == 0 && len(cntrs) == 0 {
		// export all counters (only if no groups and no counters were specified)
		prometheusExportGroup(w, &counters.RootGrp, "", buf, prFlags)
	}

	// if specific groups are requested, export only those
	if len(groups) > 0 {
		for _, grp := range groups {
			g, errpos := counters.RootGrp.GetSubGroupDot(grp)
			if g != nil {
				prefix := grp + "_"
				prometheusExportGroup(w, g, prefix, buf, prFlags)
			} else {
				// use buffer for error message
				buf.WriteString("# ERROR: counter group not found after ")
				if errpos > 0 && errpos <= len(grp) {
					buf.WriteString(strconv.Quote(grp[:errpos]))
					buf.WriteString(": ")
					buf.WriteString(strconv.Quote(grp[errpos:]))
				} else {
					buf.WriteString(strconv.Quote(grp))
				}
				buf.WriteByte('\n')
			}
		}
	}

	// if specific counters are requested, export them directly
	if len(cntrs) > 0 {
		for _, cnt := range cntrs {
			g, c, errpos := counters.RootGrp.GetCounterDot(cnt)
			if g != nil && c != counters.Invalid {
				// Export counter directly
				prometheusExportCounter(w, g, c, cnt, buf, prFlags)
			} else {
				// use buffer for error message
				buf.WriteString("# ERROR: ")
				if g == nil {
					buf.WriteString("counter group not found after ")
				} else {
					buf.WriteString("counter name not found after ")
				}
				if errpos > 0 && errpos <= len(cnt) {
					buf.WriteString(strconv.Quote(cnt[:errpos]))
					buf.WriteString(": ")
					buf.WriteString(strconv.Quote(cnt[errpos:]))
				} else {
					buf.WriteString(strconv.Quote(cnt))
				}
				buf.WriteByte('\n')
			}
		}
	}

	// write any remaining buffered data
	if buf.Len() > 0 {
		w.Write(buf.Bytes())
	}
}
