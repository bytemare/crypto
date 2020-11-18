package hash

import (
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"

	"github.com/bytemare/cryptotools/internal"
)

var errSmallOutputSize = internal.ParameterError("requested output size too small")

// XOF defines the interface to hash functions that
// support arbitrary-length output.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if called
	// after Read.
	io.Writer

	// Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset resets the XOF to its initial state.
	Reset()
}

type blake2bXOF struct {
	blake2b.XOF
}

func (b blake2bXOF) Clone() XOF {
	return blake2bXOF{b.XOF.Clone()}
}

type blake2sXOF struct {
	blake2s.XOF
}

func (b blake2sXOF) Clone() XOF {
	return blake2sXOF{b.XOF.Clone()}
}

type shake struct {
	sha3.ShakeHash
}

func (s shake) Clone() XOF {
	return shake{s.ShakeHash.Clone()}
}

// ExtensibleHash implements the the hashFunc interface for extensible output functions.
type ExtensibleHash struct {
	XOF
	minOutputSize int
}

func newShake(f func() sha3.ShakeHash, minOutputSize int) newHashFunc {
	return func() hashFunc {
		return &ExtensibleHash{XOF: &shake{f()}, minOutputSize: minOutputSize}
	}
}

func newBlake2xb() newHashFunc {
	h, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() hashFunc {
		return &ExtensibleHash{XOF: &blake2bXOF{h}, minOutputSize: size256}
	}
}

func newBlake2xs() newHashFunc {
	h, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() hashFunc {
		return &ExtensibleHash{XOF: &blake2sXOF{h}, minOutputSize: size256}
	}
}

// Hash returns the hash of the in argument with size output length.
func (h *ExtensibleHash) Hash(size int, in ...[]byte) []byte {
	if size < h.minOutputSize {
		panic(errSmallOutputSize)
	}

	h.Reset()

	for _, i := range in {
		_, _ = h.XOF.Write(i)
	}

	output := make([]byte, size)
	_, _ = h.XOF.Read(output)

	return output
}

// Hmac can't be used with extensible output functions.
func (h *ExtensibleHash) Hmac(_, _ []byte) []byte {
	panic(errForbiddenXOF)
}

// HKDF can't be used with extensible output functions.
func (h *ExtensibleHash) HKDF(_, _, _ []byte, _ int) []byte {
	panic(errForbiddenXOF)
}

// DeriveKey can't be used with extensible output functions.
func (h *ExtensibleHash) DeriveKey(_, _ []byte, _ int) []byte {
	panic(errForbiddenXOF)
}

func (h *ExtensibleHash) outputSize() int {
	return h.minOutputSize
}
