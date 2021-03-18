// Copyright 2019-2021 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

// logging functions

import (
	"github.com/intuitivelabs/slog"
)

// Log is the generic log
var Log slog.Log = slog.New(slog.LERR, slog.LbackTraceL|slog.LlocInfoL,
	slog.LStdErr)

// Plog is the log used when parsing and processing messages
var Plog slog.Log = slog.New(slog.LCRIT, slog.LOptNone, slog.LStdErr)

// WARNon() is a shorthand for checking if generic warning logging is enabled
func WARNon() bool {
	return Log.WARNon()
}

// WARN is a shorthand for logging a warning message.
func WARN(f string, a ...interface{}) {
	Log.LLog(slog.LWARN, 1, "WARNING: ", f, a...)
}

// ERRon() is a shorthand for checking if generic error logging is enabled
func ERRon() bool {
	return Log.ERRon()
}

// ERR is a shorthand for logging an error message.
func ERR(f string, a ...interface{}) {
	Log.LLog(slog.LERR, 1, "ERROR: ", f, a...)
}

// BUG is a shorthand for logging a bug message.
func BUG(f string, a ...interface{}) {
	Log.LLog(slog.LBUG, 1, "BUG: ", f, a...)
}

// PERR is a shorthand for logging a parser / processing error message.
func PERR(f string, a ...interface{}) {
	Plog.LLog(slog.LERR, 1, "ERROR: ", f, a...)
}
