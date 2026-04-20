package sipcallmon

import (
	"io"
)

// FixedIOWriter writes into a slice without exceeding its capacity.
// It reuses the slice's length to track how much has been written.
type FixedIOWriter struct {
	Buf []byte
}

// NewFixedIOWriter creates a writer over an existing slice.
// The slice may have len < cap to allow room for writing.
func NewFixedIOWriter(b []byte) *FixedIOWriter {
	return &FixedIOWriter{Buf: b}
}

// Write implements io.Writer.
// It appends data to the slice without exceeding its capacity.
func (w *FixedIOWriter) Write(p []byte) (int, error) {
	n := cap(w.Buf) - len(w.Buf)
	if len(p) > n {
		// write only what it fits in the available space
		w.Buf = append(w.Buf, p[:n]...)
		return n, io.ErrShortWrite
	}
	w.Buf = append(w.Buf, p...)
	return len(p), nil
}
