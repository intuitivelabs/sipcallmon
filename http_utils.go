// Copyright 2019-2020 Intuitive Labs GmbH. All rights reserved.
//
// Use of this source code is governed by a source-available license
// that can be found in the LICENSE.txt file in the root of the source
// tree.

package sipcallmon

import (
	"fmt"
	"net/http"
	"strconv"
)

// look for a form parameter named n and return the value as uint.
// If errPrint is true, an error message will be output to w.
// Returns: (value, found, error)
//   - if found == false the value will be set to 0.
//   - on error :  found == false and value = 0
//   - on success: found = true
func getUintFormVal(w http.ResponseWriter, r *http.Request,
	n string, errPrint bool) (uint64, bool, error) {
	s := r.FormValue(n)
	if len(s) > 0 {
		if v, err := strconv.ParseUint(s, 10, 64); err == nil {
			return v, true, nil
		} else {
			if errPrint {
				fmt.Fprintf(w, "ERROR: bad %s value (%q) : %s\n",
					n, s, err)
			}
			return 0, false, err
		}
	}
	return 0, false, nil
}

// look for a form parameter named n and return the value as uint.
// If errPrint is true, an error message will be output to w.
// Returns: (value, found, error)
//   - if found == false the value will be set to 0.
//   - on error :  found == false and value = 0
//   - on success: found = true
func getIntFormVal(w http.ResponseWriter, r *http.Request,
	n string, errPrint bool) (int64, bool, error) {
	s := r.FormValue(n)
	if len(s) > 0 {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			return v, true, nil
		} else {
			if errPrint {
				fmt.Fprintf(w, "ERROR: bad %s value (%q) : %s\n",
					n, s, err)
			}
			return 0, false, err
		}
	}
	return 0, false, nil
}
