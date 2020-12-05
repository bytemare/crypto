// Package hash provides an interface to hashing functions.
package hash

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/sha3"
)

// Identifier defines registered hashing engines for use in the implementation.
type Identifier byte

const (
	// SHA256 identifies the Sha2 hashing function with 256 bit output.
	SHA256 Identifier = 1 + iota

	// SHA512 identifies the Sha2 hashing function with 512 bit output.
	SHA512

	// SHA3_256 identifies the Sha3 hashing function with 256 bit output.
	SHA3_256

	// SHA3_512 identifies the Sha3 hashing function with 512 bit output.
	SHA3_512

	// SHAKE128 identifies the SHAKE128 Extendable-Output Function.
	SHAKE128

	// SHAKE256 identifies the SHAKE256 Extendable-Output Function.
	SHAKE256

	// BLAKE2XB identifies the BLAKE2XB Extendable-Output Function.
	BLAKE2XB

	// BLAKE2XS identifies the BLAKE2XS Extendable-Output Function.
	BLAKE2XS

	maxID

	// string IDs for the hash functions.
	sha256s   = "SHA256"
	sha512s   = "SHA512"
	sha3_256s = "SHA3-256"
	sha3_512s = "SHA3-512"
	shake128  = "SHAKE128"
	shake256  = "SHAKE256"
	blake2xb  = "BLAKE2XB"
	blake2xs  = "BLAKE2XS"

	// output size in bytes.
	size256 = 32
	size512 = 64

	// security level in bits.
	sec128 = 128
	sec256 = 256

	// block size in bytes.
	blockSHA3256  = 1088 / 8
	blockSHA3512  = 576 / 8
	blockSHAKE128 = 1344 / 8
	blockSHAKE256 = 1088 / 8

	// Default hash to use.
	Default = SHA3_512
)

var (
	errHmacKeySize  = errors.New("hmac key length is larger than hash output size")
	errForbiddenXOF = errors.New("function not supported with XOF")
)

var registered map[Identifier]*params

// Get returns a pointer to an initialised Hash structure for the according has primitive.
func (i Identifier) Get() *Hash {
	p := registered[i]

	return &Hash{
		id:         p.id,
		name:       p.name,
		hashFunc:   p.newHashFunc(),
		blockSize:  p.blockSize,
		security:   p.security,
		extensible: p.extensible,
	}
}

// Available reports whether the given hash function is linked into the binary.
func (i Identifier) Available() bool {
	return i < maxID && registered[i] != nil
}

func (i Identifier) String() string {
	return registered[i].name
}

func (i Identifier) register(x newHashFunc, name string, blockSize, security int, extensible bool) {
	registered[i] = &params{
		id:          i,
		name:        name,
		newHashFunc: x,
		blockSize:   blockSize,
		security:    security,
		extensible:  extensible,
	}
}

func init() {
	registered = make(map[Identifier]*params)

	SHA256.register(newFixedOutputHash(crypto.SHA256, sha256.New, sha256.Size), sha256s, sha256.BlockSize, sec128, false)
	SHA512.register(newFixedOutputHash(crypto.SHA512, sha512.New, sha512.Size), sha512s, sha512.BlockSize, sec256, false)
	SHA3_256.register(newFixedOutputHash(crypto.SHA3_256, sha3.New256, size256), sha3_256s, blockSHA3256, sec128, false)
	SHA3_512.register(newFixedOutputHash(crypto.SHA3_512, sha3.New512, size512), sha3_512s, blockSHA3512, sec256, false)

	SHAKE128.register(newShake(sha3.NewShake128, size256), shake128, blockSHAKE128, sec128, true)
	SHAKE256.register(newShake(sha3.NewShake256, size512), shake256, blockSHAKE256, sec256, true)
	BLAKE2XB.register(newBlake2xb(), blake2xb, 0, sec128, true)
	BLAKE2XS.register(newBlake2xs(), blake2xs, 0, sec128, true)
}

type newHashFunc func() hashFunc

type hashFunc interface {
	Hash(size int, in ...[]byte) []byte
	Hmac(message, key []byte) []byte
	HKDF(secret, salt, info []byte, length int) []byte
	HKDFExtract(secret, salt []byte) []byte
	HKDFExpand(pseudorandomKey, info []byte, length int) []byte
	outputSize() int
}

type params struct {
	name string
	newHashFunc
	blockSize  int
	security   int
	id         Identifier
	extensible bool
}

// Hash offers easy an easy to use API for common cryptographic hash operations.
type Hash struct {
	name string
	hashFunc
	blockSize  int
	security   int
	id         Identifier
	extensible bool
}

// Identifier returns the hash function's ID.
func (h *Hash) Identifier() Identifier {
	return h.id
}

// BlockSize returns the hash's output size in bytes for SHA2 and SHA3 hashes,
// and the minimum output for full the security strength if it is a XOF.
func (h *Hash) BlockSize() int {
	return h.blockSize
}

// OutputSize returns the hash's output size in bytes for SHA2 and SHA3 hashes,
// and the minimum output for full security strength if it is a XOF.
func (h *Hash) OutputSize() int {
	return h.hashFunc.outputSize()
}

// Extensible returns whether the hash function is and extensible output function.
func (h *Hash) Extensible() bool {
	return h.extensible
}

// SecurityLevel returns the hash function's bit security level.
func (h *Hash) SecurityLevel() int {
	return h.security
}

// String returns the hash function's common name.
func (h *Hash) String() string {
	return h.name
}
