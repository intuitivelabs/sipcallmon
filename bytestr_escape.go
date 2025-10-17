// functions for escaping []byte stored strings into various "safe" formats
package sipcallmon

import (
	"errors"
)

var errPathEscDstTooSmall = errors.New("escaped path destination slice too small")
var errFileEscDstTooSmall = errors.New("escaped file destination slice too small")
var errUrlEscDstTooSmall = errors.New("escaped url destination slice too small")

// FileEscapeSafe writes a "safe" file-escaped version of src into dst.
// It escapes possible problematic characters beyond what is allowed on
// a typical unix system (e.g. '~', '&', '!', '*', '#', '|')
// '%' is used for escaping disallowed characters ("%##" where
// "##" are hex digits).
// It returns the number of bytes written or an error if dst is too small.
// To make sure dst is always large enough, it's size must be >= 3*len(src).
func FileEscapeSafe(dst, src []byte) (int, error) {
	const hex = "0123456789ABCDEF"
	max := len(dst)
	j := 0
	if len(dst) >= 3*len(src) {
		// fast path
		for i := 0; i < len(src); i++ {
			c := src[i]
			switch {
			case
				(c >= 'A' && c <= 'z') || // A-Z [ \ ] ^ _  a-z
					(c >= '0' && c <= '9') ||
					c == ' ' || c == '"' ||
					c == '(' || c == ')' ||
					c == '+' || c == ',' ||
					c == '-' || c == '.' || c == ':' ||
					c == '=' || c == '?' || c == '@' ||
					c == '{' || c == '}':
				dst[j] = c
				j++
			default:
				// Percent-encode the others
				dst[j+0] = '%'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0x0F]
				j += 3
			}
		}
	} else {
		// slow path (check dst len at each step)
		for i := 0; i < len(src); i++ {
			c := src[i]
			switch {
			case
				(c >= 'A' && c <= 'z') || // A-Z [ \ ] ^ _  a-z
					(c >= '0' && c <= '9') ||
					c == ' ' || c == '"' ||
					c == '(' || c == ')' ||
					c == '+' || c == ',' ||
					c == '-' || c == '.' || c == ':' ||
					c == '=' || c == '?' || c == '@' ||
					c == '{' || c == '}':
				if j >= max {
					return max, errFileEscDstTooSmall
				}
				dst[j] = c
				j++
			default:
				if j+3 > max {
					return j, errFileEscDstTooSmall
				}
				// Percent-encode the others
				dst[j+0] = '%'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0x0F]
				j += 3
			}
		}
	}
	return j, nil
}

// URLEscape writes an url-escaped version of src into dst.
// The allowed (un-escaped) characters are [0-9A-Za-z_.~%-].
// '%' is used for escaping disallowed characters ("%##" where
// "##" are hex digits).
// It returns the number of bytes written or an error if dst is too small.
// To make sure dst is always large enough, it's size must be >= 3*len(src).
func URLEscape(dst, src []byte) (int, error) {
	const hex = "0123456789ABCDEF"
	max := len(dst)
	j := 0
	if len(dst) >= 3*len(src) {
		// fast path (no length checks)
		for i := 0; i < len(src); i++ {
			c := src[i]
			switch {
			case (c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '_' || c == '.' || c == '~':
				dst[j] = c
				j++
			default:
				// Percent-encode the others
				dst[j+0] = '%'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0x0F]
				j += 3
			}
		}
	} else {
		// slow path (check dst len at each step)
		for i := 0; i < len(src); i++ {
			c := src[i]
			switch {
			case (c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '_' || c == '.' || c == '~':
				if j >= max {
					return max, errUrlEscDstTooSmall
				}
				dst[j] = c
				j++
			default:
				if j+3 > max {
					return j, errUrlEscDstTooSmall
				}
				// Percent-encode the others
				dst[j+0] = '%'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0x0F]
				j += 3
			}
		}
	}
	return j, nil
}

// UploadIdEscape writes an escaped version of src into dst.
// The allowed (un-escaped) characters are [0-9A-Za-z_-].
// '_' is used for escaping disallowed characters ("_##" where
// "##" are hex digits or "__" for a single '_').
// The escaped string is not allowed to start or end with '-' (in this case
// it will be escaped: _2d).
// It returns the number of bytes written or an error if dst is too small.
// To make sure dst is always large enough, it's size must be >= 3*len(src).
func UploadIdEscape(dst, src []byte) (int, error) {
	const hex = "0123456789abcdef"

	i := 0
	j := 0
	max := len(dst)

	if len(dst) >= 3*len(src) && len(src) > 0 {
		// fast path (no length checks)
		// fix leading '-'
		if src[0] == '-' {
			dst[0] = '_'
			dst[1] = '_'
			i = 1
			j = 2
		}
		for ; i < len(src); i++ {
			c := src[i]
			if (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				c == '-' { // '_' kept as escape character
				dst[j] = c
				j++
			} else if c == '_' {
				dst[j+0] = '_'
				dst[j+1] = '_'
				j += 2
			} else {
				dst[j+0] = '_'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0xF]
				j += 3
			}
		}
		// fix trailing '-'
		if j > 0 {
			if dst[j-1] == '-' {
				dst[j-1] = '_'
				dst[j] = '-'
				j++
			}
		}
	} else {
		// slow path (check dst len at each step)
		// fix leading '-'
		if len(src) > 0 && src[0] == '-' {
			if 2 > max {
				return 0, errUrlEscDstTooSmall
			}
			dst[0] = '_'
			dst[1] = '_'
			i = 1
			j = 2
		}
		for ; i < len(src); i++ {
			c := src[i]
			if (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'z') ||
				(c >= 'A' && c <= 'Z') ||
				c == '-' { // '_' kept as escape character
				if j >= max {
					return max, errUrlEscDstTooSmall
				}
				dst[j] = c
				j++
			} else if c == '_' {
				if j+2 > max {
					return j, errUrlEscDstTooSmall
				}
				dst[j+0] = '_'
				dst[j+1] = '_'
				j += 2
			} else {
				if j+3 > max {
					return j, errUrlEscDstTooSmall
				}
				dst[j+0] = '_'
				dst[j+1] = hex[c>>4]
				dst[j+2] = hex[c&0xF]
				j += 3
			}
		}
		// fix trailing '-'
		if j > 0 {
			if dst[j-1] == '-' {
				dst[j-1] = '_'
				if j+1 > max {
					return j, errUrlEscDstTooSmall
				}
				dst[j] = '-'
				j++
			}
		}
	}

	return j, nil
}
