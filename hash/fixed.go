// Package hash provides an interface to hashing functions.
package hash

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Hashing defines registered fixed length hashing engines.
type Hashing byte

const (
	// SHA256 identifies the Sha2 hashing function with 256 bit output.
	SHA256 Hashing = 1 + iota

	// SHA512 identifies the Sha2 hashing function with 512 bit output.
	SHA512

	// SHA3_256 identifies the Sha3 hashing function with 256 bit output.
	SHA3_256

	// SHA3_512 identifies the Sha3 hashing function with 512 bit output.
	SHA3_512

	maxHashing

	// string IDs for the hash functions.
	sha256s   = "SHA256"
	sha512s   = "SHA512"
	sha3_256s = "SHA3-256"
	sha3_512s = "SHA3-512"

	// block size in bytes.
	blockSHA3256 = 1088 / 8
	blockSHA3512 = 576 / 8

	// Default hash to use.
	Default = SHA512
)

var errHmacKeySize = errors.New("hmac key length is larger than hash output size")

type fixedParams struct {
	parameters
	newHashFunc func() hash.Hash
}

var registeredHashing map[Hashing]*fixedParams

// Get returns a pointer to an initialised Hash structure for the according has primitive.
func (i Hashing) Get() *Hash {
	return &Hash{
		Hashing: i,
		f:       registeredHashing[i].newHashFunc,
		hash:    registeredHashing[i].newHashFunc(),
	}
}

// Available reports whether the given hash function is linked into the binary.
func (i Hashing) Available() bool {
	return i < maxHashing && registeredHashing[i] != nil
}

// BlockSize returns the hash's block size.
func (i Hashing) BlockSize() int {
	return registeredHashing[i].blockSize
}

// OutputSize returns the hash's output size in bytes for SHA2 and SHA3 hashes,
// and the minimum output for full security strength if it is a XOF.
func (i Hashing) OutputSize() int {
	return registeredHashing[i].outputSize
}

// Size returns the number of bytes the hash function will return,
// and the minimum output for full security strength if it is a XOF.
func (i Hashing) Size() int {
	return registeredHashing[i].outputSize
}

// SecurityLevel returns the hash function's bit security level.
func (i Hashing) SecurityLevel() int {
	return registeredHashing[i].security
}

// String returns the hash function's common name.
func (i Hashing) String() string {
	return registeredHashing[i].name
}

func (i Hashing) register(f func() hash.Hash, name string, blockSize, outputSize, security int) {
	registeredHashing[i] = &fixedParams{
		parameters: parameters{
			name:       name,
			blockSize:  blockSize,
			outputSize: outputSize,
			security:   security,
		},
		newHashFunc: f,
	}
}

func init() {
	registeredHashing = make(map[Hashing]*fixedParams)

	SHA256.register(sha256.New, sha256s, sha256.BlockSize, sha256.Size, sec128)
	SHA512.register(sha512.New, sha512s, sha512.BlockSize, sha512.Size, sec256)
	SHA3_256.register(sha3.New256, sha3_256s, blockSHA3256, size256, sec128)
	SHA3_512.register(sha3.New512, sha3_512s, blockSHA3512, size512, sec256)
}

// Hash offers easy an easy to use API for common cryptographic hash operations.
type Hash struct {
	Hashing
	f    func() hash.Hash
	hash hash.Hash
}

// Write implements io.Writer
func (h *Hash) Write(p []byte) (n int, err error) {
	return h.hash.Write(p)
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *Hash) Sum(b []byte) []byte {
	return h.hash.Sum(b)
}

// Reset resets the Hash to its initial state.
func (h *Hash) Reset() {
	h.hash.Reset()
}

// Hash returns the hash of the input arguments.
func (h *Hash) Hash(input ...[]byte) []byte {
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}

// Hmac wraps the built-in hmac.
func (h *Hash) Hmac(message, key []byte) []byte {
	if len(key) > h.OutputSize() {
		panic(errHmacKeySize)
	}

	hm := hmac.New(h.f, key)
	hm.Write(message)

	return hm.Sum(nil)
}

// HKDF is an "extract-then-expand" HMAC based Key derivation function,
// where info is the specific usage identifying information.
func (h *Hash) HKDF(secret, salt, info []byte, length int) []byte {
	if length == 0 {
		length = h.OutputSize()
	}

	kdf := hkdf.New(h.f, secret, salt, info)
	dst := make([]byte, length)

	_, _ = io.ReadFull(kdf, dst)

	return dst
}

// HKDFExtract is an "extract" only HKDF, where the secret and salt are used to generate a pseudorandom key. This key
// can then be used in multiple HKDFExpand calls to derive individual different keys.
func (h *Hash) HKDFExtract(secret, salt []byte) []byte {
	return hkdf.Extract(h.f, secret, salt)
}

// HKDFExpand is an "expand" only HKDF, where the key should be an already random/hashed input,
// and info specific key usage identifying information.
func (h *Hash) HKDFExpand(pseudorandomKey, info []byte, length int) []byte {
	if length == 0 {
		length = h.OutputSize()
	}

	kdf := hkdf.Expand(h.f, pseudorandomKey, info)
	dst := make([]byte, length)

	_, _ = kdf.Read(dst)

	return dst
}
