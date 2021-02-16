package hash

import (
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"

	"github.com/bytemare/cryptotools/internal"
)

// Extensible identifies Extendable-Output Functions.
type Extensible byte

const (
	// SHAKE128 identifies the SHAKE128 Extendable-Output Function.
	SHAKE128 Extensible = 1 + iota

	// SHAKE256 identifies the SHAKE256 Extendable-Output Function.
	SHAKE256

	// BLAKE2XB identifies the BLAKE2XB Extendable-Output Function.
	BLAKE2XB

	// BLAKE2XS identifies the BLAKE2XS Extendable-Output Function.
	BLAKE2XS

	maxXOF

	// string IDs for the hash functions.
	shake128 = "SHAKE128"
	shake256 = "SHAKE256"
	blake2xb = "BLAKE2XB"
	blake2xs = "BLAKE2XS"

	// block size in bytes.
	blockSHAKE128 = 1344 / 8
	blockSHAKE256 = 1088 / 8
)

type xofParams struct {
	parameters
	newHashFunc newXOF
}

var registeredXOF map[Extensible]*xofParams

// Get returns a pointer to an initialised Hash structure for the according has primitive.
func (e Extensible) Get() *ExtensibleHash {
	p := registeredXOF[e]
	h := p.newHashFunc()
	h.Extensible = e

	return h
}

// Available reports whether the given hash function is linked into the binary.
func (e Extensible) Available() bool {
	return e < maxXOF && registeredXOF[e] != nil
}

// BlockSize returns the hash's block size.
func (e Extensible) BlockSize() int {
	return registeredXOF[e].blockSize
}

// Extensible returns whether the hash function is extensible, therefore always true.
func (e Extensible) Extensible() bool {
	return true
}

// Hash returns the hash of the input arguments.
func (e Extensible) Hash(size int, input ...[]byte) []byte {
	return e.Get().Hash(size, input...)
}

// MinOutputSize returns the minimal output length necessary to guarantee its bit security level.
func (e Extensible) MinOutputSize() int {
	return e.Get().minOutputSize
}

// SecurityLevel returns the hash function's bit security level.
func (e Extensible) SecurityLevel() int {
	return registeredXOF[e].security
}

// String returns the hash function's common name.
func (e Extensible) String() string {
	return registeredXOF[e].name
}

func (e Extensible) register(f newXOF, name string, blockSize, outputSize, security int) {
	registeredXOF[e] = &xofParams{
		parameters: parameters{
			name:       name,
			blockSize:  blockSize,
			outputSize: outputSize,
			security:   security,
		},
		newHashFunc: f,
	}
}

type newXOF func() *ExtensibleHash

func init() {
	registeredXOF = make(map[Extensible]*xofParams)

	SHAKE128.register(newShake(sha3.NewShake128, size256), shake128, blockSHAKE128, size256, sec128)
	SHAKE256.register(newShake(sha3.NewShake256, size512), shake256, blockSHAKE256, size512, sec256)
	BLAKE2XB.register(newBlake2xb(), blake2xb, 0, size256, sec128)
	BLAKE2XS.register(newBlake2xs(), blake2xs, 0, size256, sec128)
}

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

func newShake(f func() sha3.ShakeHash, minOutputSize int) newXOF {
	return func() *ExtensibleHash {
		return &ExtensibleHash{XOF: &shake{f()}, minOutputSize: minOutputSize}
	}
}

func newBlake2xb() newXOF {
	h, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() *ExtensibleHash {
		return &ExtensibleHash{XOF: &blake2bXOF{h}, minOutputSize: size256}
	}
}

func newBlake2xs() newXOF {
	h, err := blake2s.NewXOF(blake2s.OutputLengthUnknown, nil)
	if err != nil {
		panic(err)
	}

	return func() *ExtensibleHash {
		return &ExtensibleHash{XOF: &blake2sXOF{h}, minOutputSize: size256}
	}
}

// ExtensibleHash wraps extensible output functions.
type ExtensibleHash struct {
	Extensible
	XOF
	minOutputSize int
}

// Hash returns the hash of the input argument with size output length.
func (h *ExtensibleHash) Hash(size int, input ...[]byte) []byte {
	if size < h.minOutputSize {
		panic(errSmallOutputSize)
	}

	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	output := make([]byte, size)
	_, _ = h.XOF.Read(output)

	return output
}

// Write implements io.Writer
func (h *ExtensibleHash) Write(p []byte) (n int, err error) {
	return h.XOF.Write(p)
}

// Read returns size bytes from the current hash.
func (h *ExtensibleHash) Read(size int) []byte {
	if size < h.minOutputSize {
		panic(errSmallOutputSize)
	}

	output := make([]byte, size)
	_, _ = h.XOF.Read(output)

	return output
}

// Reset resets the Hash to its initial state.
func (h *ExtensibleHash) Reset() {
	h.XOF.Reset()
}
