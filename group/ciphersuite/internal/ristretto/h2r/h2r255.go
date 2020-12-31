// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"math"

	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/internal"
)

const (
	dstMaxLength  = 255
	dstLongPrefix = "H2C-OVERSIZE-DST-"
)

var (
	errZeroLenDST = internal.ParameterError("zero-length DST")
	errShortDST   = internal.ParameterError("DST is shorter than recommended length")
)

// HashToRistretto allows hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
type HashToRistretto struct {
	*hash.Hash
	originalDST []byte
	dst         []byte
}

// New returns a newly instantiated HashToRistretto structure.
func New(dst []byte, id hash.Identifier) *HashToRistretto {
	h := &HashToRistretto{
		Hash:        id.Get(),
		originalDST: dst,
	}
	h.setDST(dst)

	return h
}

// Expand expands the input by hashing using the expandMessageXMD or expandMessageXOF functions from hash-to-curve.
func (h *HashToRistretto) Expand(input []byte, length int) []byte {
	if len(h.dst) < group.DstRecommendedMinLength {
		if len(h.dst) == group.DstMinLength {
			panic(errZeroLenDST)
		}

		panic(errShortDST)
	}

	// todo: what happens when input is nil ?
	if h.Extensible() {
		return h.expandMessageXOF(input, length)
	}

	return h.expandMessageXMD(input, length)
}

func (h *HashToRistretto) setDST(dst []byte) {
	if len(dst) <= dstMaxLength {
		h.dst = dst
		return
	}

	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	ext := append([]byte(dstLongPrefix), dst...)

	size := h.OutputSize()

	if h.Extensible() {
		k := h.SecurityLevel()
		size = int(math.Ceil(float64(2 * k / 8)))
	}

	h.dst = h.Hash.Hash(size, ext)
}

// GetOriginalDST returns the DST as given as input on instantiating of h.
// If the DST was too long it has been hashed afterwards in setDST. This returns the unmodified DST.
func (h *HashToRistretto) GetOriginalDST() string {
	return string(h.originalDST)
}
