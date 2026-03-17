package sipcallmon

// pcapRotFmtOp identifies a format segment operation for rotated filenames.
type pcapRotFmtOp uint8

const (
	rotFmtLiteral       pcapRotFmtOp = iota // literal bytes
	rotFmtBase                              // %b - original base (no ext)
	rotFmtExt                               // %e - original extension
	rotFmtFull                              // %f - original filename
	rotFmtDir                               // %d - original directory
	rotFmtTsSec                             // %s - unix seconds
	rotFmtTsMs                              // %ms - unix milliseconds
	rotFmtTsNs                              // %ns - unix nanoseconds
	rotFmtTimeLayout                        // %t{layout} - Go time format
	rotFmtRand                              // %r - random hex uint32 (always)
	rotFmtUploadId                          // %i - PcapUploadId(key)
	rotFmtSeq                               // %n - monotonic counter (always)
	rotFmtConflictRand                      // %R - random hex (conflict-only)
	rotFmtConflictSeq                       // %N - monotonic counter (conflict-only)
	rotFmtConflictRetry                     // %U - retry counter (conflict-only)
)

// pcapRotFmtSeg is one segment of a compiled rotate format string.
type pcapRotFmtSeg struct {
	op  pcapRotFmtOp
	lit string // literal text or time layout
}

// parseRotateFmt compiles a format string into a list of segments.
// Returns nil if the format string is empty.
// Also returns whether any conflict-only ops (%R, %N, %U) are present.
func parseRotateFmt(fmt string) ([]pcapRotFmtSeg, bool) {
	if len(fmt) == 0 {
		return nil, false
	}
	var segs []pcapRotFmtSeg
	hasRetry := false
	litStart := 0
	i := 0
	for i < len(fmt) {
		if fmt[i] != '%' {
			i++
			continue
		}
		// flush literal before this %
		if i > litStart {
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: fmt[litStart:i]})
		}
		i++ // skip '%'
		if i >= len(fmt) {
			break
		}
		switch fmt[i] {
		case '%':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%"})
			i++
		case 'b':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtBase})
			i++
		case 'e':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtExt})
			i++
		case 'f':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtFull})
			i++
		case 'd':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtDir})
			i++
		case 's':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtTsSec})
			i++
		case 'm':
			// %ms
			if i+1 < len(fmt) && fmt[i+1] == 's' {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtTsMs})
				i += 2
			} else {
				// unknown, treat as literal
				segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%m"})
				i++
			}
		case 'n':
			// %ns or %n
			if i+1 < len(fmt) && fmt[i+1] == 's' {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtTsNs})
				i += 2
			} else {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtSeq})
				i++
			}
		case 't':
			// %t{layout}
			i++
			if i < len(fmt) && fmt[i] == '{' {
				end := i + 1
				for end < len(fmt) && fmt[end] != '}' {
					end++
				}
				if end < len(fmt) {
					layout := fmt[i+1 : end]
					segs = append(segs, pcapRotFmtSeg{op: rotFmtTimeLayout, lit: layout})
					i = end + 1
				} else {
					// unterminated {, treat as literal
					segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%t"})
				}
			} else {
				segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: "%t"})
			}
		case 'r':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtRand})
			i++
		case 'i':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtUploadId})
			i++
		case 'R':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictRand})
			hasRetry = true
			i++
		case 'N':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictSeq})
			hasRetry = true
			i++
		case 'U':
			segs = append(segs, pcapRotFmtSeg{op: rotFmtConflictRetry})
			hasRetry = true
			i++
		default:
			// unknown specifier, emit as literal
			segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral,
				lit: fmt[i-1 : i+1]})
			i++
		}
		litStart = i
	}
	// flush trailing literal
	if litStart < len(fmt) {
		segs = append(segs, pcapRotFmtSeg{op: rotFmtLiteral, lit: fmt[litStart:]})
	}
	return segs, hasRetry
}

// splitOldName splits oldName into directory (without trailing /),
// base name (without extension), and extension (with leading dot).
// All returned slices point into oldName (no allocation).
func splitOldName(oldName []byte) (dir, baseName, ext []byte) {
	// find last '/' for dir/base split
	dirEnd := -1
	for i := len(oldName) - 1; i >= 0; i-- {
		if oldName[i] == '/' {
			dirEnd = i
			break
		}
	}

	var base []byte
	if dirEnd >= 0 {
		dir = oldName[:dirEnd]
		base = oldName[dirEnd+1:]
	} else {
		base = oldName
	}

	// find last '.' in base for extension split
	extIdx := -1
	for i := len(base) - 1; i >= 0; i-- {
		if base[i] == '.' {
			extIdx = i
			break
		}
	}
	if extIdx >= 0 {
		baseName = base[:extIdx]
		ext = base[extIdx:]
	} else {
		baseName = base
	}
	return
}

// appendHex32 appends v as 8 lowercase hex digits to buf (zero-alloc).
func appendHex32(buf []byte, v uint32) []byte {
	const hexDigits = "0123456789abcdef"
	var tmp [8]byte
	for i := 7; i >= 0; i-- {
		tmp[i] = hexDigits[v&0xf]
		v >>= 4
	}
	return append(buf, tmp[:]...)
}
