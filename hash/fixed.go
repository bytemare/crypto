package hash

import (
	"crypto"
	"crypto/hmac"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/bytemare/cryptotools/internal"
)

// FixedHash implements the hashFunc interface for fixed length output hash functions.
type FixedHash struct {
	hashID crypto.Hash
	hash   func() hash.Hash
	size   int
}

var errHashID = internal.ParameterError("hash function unknown or not available")

func newFixedOutputHash(id crypto.Hash, f func() hash.Hash, outputSize int) newHashFunc {
	return func() hashFunc {
		if !id.Available() {
			panic(errHashID)
		}

		return &FixedHash{
			hashID: id,
			hash:   f,
			size:   outputSize,
		}
	}
}

// Hash returns the hash of the in argument.
func (h *FixedHash) Hash(_ int, in ...[]byte) []byte {
	f := h.hash()
	f.Reset()

	for _, i := range in {
		_, _ = f.Write(i)
	}

	return f.Sum(nil)
}

// Hmac wraps the built-in hmac.
func (h *FixedHash) Hmac(message, key []byte) []byte {
	if len(key) > h.size {
		panic(errHmacKeySize)
	}

	hm := hmac.New(h.hash, key)
	hm.Write(message)

	return hm.Sum(nil)
}

// HKDF is an "extract-then-expand" HMAC based Key derivation function,
// where info is the specific usage identifying information.
func (h *FixedHash) HKDF(secret, salt, info []byte, length int) []byte {
	if length == 0 {
		length = h.size
	}

	kdf := hkdf.New(h.hash, secret, salt, info)
	dst := make([]byte, length)

	_, _ = io.ReadFull(kdf, dst)

	return dst
}

// HKDFExtract is an "extract" only HKDF, where the secret and salt are used to generate a pseudorandom key. This key
// can then be used in multiple HKDFExpand calls to derive individual different keys.
func (h *FixedHash) HKDFExtract(secret, salt []byte) []byte {
	return hkdf.Extract(h.hash, secret, salt)
}

// HKDFExpand is an "expand" only HKDF, where the key should be an already random/hashed input,
// and info specific key usage identifying information.
func (h *FixedHash) HKDFExpand(pseudorandomKey, info []byte, length int) []byte {
	if length == 0 {
		length = h.size
	}

	kdf := hkdf.Expand(h.hash, pseudorandomKey, info)
	dst := make([]byte, length)

	_, _ = kdf.Read(dst)

	return dst
}

func (h *FixedHash) outputSize() int {
	return h.size
}
