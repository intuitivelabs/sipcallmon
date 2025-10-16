package sipcallmon

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/cespare/xxhash/v2"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
)

var errUrlEncDstTooSmall = errors.New("url-encoded destination slice too small")

// URLEncodedLen returns the maximum length of the url encoded format
//
//	for srcLen bytes.
func URLEncodedLen(srcLen int) int {
	return base64.RawURLEncoding.EncodedLen(srcLen)
}

// URLEncode writes an URL-safe ASCII format for src into dst.
// It returns the number of bytes written or an error if dst is too small.
func URLEncode(dst, src []byte) (int, error) {
	encodedLen := base64.RawURLEncoding.EncodedLen(len(src))
	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}
	// encode into provided dst
	base64.RawURLEncoding.Encode(dst[:encodedLen], src[:])
	return encodedLen, nil
}

// HashURLSafe is the generic type for the hash to url friendly string
// function defined below
type HashURLSafe func(dst, src []byte) (int, error)

// MD5URLSafe writes the URL-safe (base64, no padding) ASCII representation
// of md5(src) into dst.
// It returns the number of bytes written (always 22) or an error if dst is
// too small.
//
// dst must have length >= 22. This function makes no heap allocations.
func MD5URLSafe(dst, src []byte) (int, error) {
	const digestLen = 16
	encodedLen := URLEncodedLen(digestLen) // => 22b for base64 unpadded

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	// compute MD5 into fixed-size array (no allocation).
	sum := md5.Sum(src) // [16]byte

	// encode into provided dst (no allocation).
	return URLEncode(dst[:encodedLen], sum[:])
}

// SHA256URLSafe writes the URL-safe (base64, no padding) ASCII representation
// of sha256(src) into dst.
// It returns the number of bytes written (always 43) or an error if dst is
// too small.
//
// dst must have length >= 43. This function makes no heap allocations.
func SHA256URLSafe(dst, src []byte) (int, error) {
	const digestLen = 32
	encodedLen := URLEncodedLen(digestLen) // => 43b for base64 unpadded

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	// compute MD5 into fixed-size array (no allocation).
	sum := sha256.Sum256(src) // [32]byte

	// encode into provided dst (no allocation).
	return URLEncode(dst[:encodedLen], sum[:])
}

// XXHashURLSafe computes xxHash64 of src and writes its URL-safe
// base64 (no padding) ASCII encoding into dst.
// Returns number of bytes written (always 11) or an error if dst is
// too small.
func XXHashURLSafe(dst, src []byte) (int, error) {
	const digestLen = 8
	encodedLen := URLEncodedLen(digestLen) // 11 for base64 unpadded

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	var tmp [8]byte
	//xxhash -> optimised, native assembler version
	binary.LittleEndian.PutUint64(tmp[:], xxhash.Sum64(src))

	return URLEncode(dst[:encodedLen], tmp[:])
}

// XXHash128URLSafe computes xxHash128 of src and writes its URL-safe
// base64 (no padding) ASCII encoding into dst.
// Returns number of bytes written (always 11) or an error if dst is
// too small.
func XXHash128URLSafe(dst, src []byte) (int, error) {
	const digestLen = 16
	encodedLen := URLEncodedLen(digestLen) // 22 for base64 unpadded

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	// xxh3 - pure go, support for 128bits
	sum := xxh3.Hash128(src).Bytes()

	return URLEncode(dst[:encodedLen], sum[:])
}

// Blake3URLSafe256 computes the 256-bit (32-byte) BLAKE3 hash of src
// and writes it into dst as URL-safe base64 (no padding).
// Returns the number of bytes written (always 43).
// dst must be at least 43 bytes long.
func Blake3URLSafe256(dst, src []byte) (int, error) {
	const digestLen = 32
	encodedLen := URLEncodedLen(digestLen) // 43b for base64 unpadded

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	// assuming len(src)  < 1024 (blake3/internal consts.ChunLen)
	// blake3.Sum256 will use sumSmall() => no need for Hash & Hash.Reset()
	sum := blake3.Sum256(src)
	// encode as URL-safe into dst
	return URLEncode(dst[:encodedLen], sum[:])
}

// Blake3URLSafe384 computes the 384-bit (48-byte) BLAKE3 hash of src
// and writes it into dst as URL-safe base64 (no padding).
// Returns the number of bytes written (always 64).
// dst must be at least 64 bytes long.
func Blake3URLSafe384(dst, src []byte) (int, error) {
	const digestLen = 48
	encodedLen := URLEncodedLen(digestLen) // 64

	if len(dst) < encodedLen {
		return 0, errUrlEncDstTooSmall
	}

	/*
		// fixed-size digest on stack
		var digest [digestLen]byte

		// compute BLAKE3 hash
		hasher := blake3.New()
		hasher.Write(src)
		// hasher.Sum(digest[:0]) // fills max. 32 bytes
		d := hasher.Digest() // fills everything, but might escape to heap
		d.Read(digest[:])
		// TODO: hasher reuse: add hasher pointer and
		//       use hasher.Reset() to avoid the slow New()

		// Encode as URL-safe base64 (no padding) into dst
		return URLEncode(dst[:encodedLen], digest[:])
	*/

	// Sum512 version: use only 48 bytes of the output
	// (this version avoid a possible heap allocation in  hasher.Digest())
	// blake3.Sum512 will use sumSmall() => no need for Hash & Hash.Reset()
	sum := blake3.Sum512(src)
	// encode as URL-safe into dst
	return URLEncode(dst[:encodedLen], sum[:digestLen])
}

// other options:
//  farmhash - 128 bit
//  siphash  64 or 128 , crypto, slow
//  shake / sha-3 xof - any, crypto, slower then blake
