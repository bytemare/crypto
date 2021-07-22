// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"

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

type Expander interface {
	expandMessage(input, dst []byte, length int) []byte
	vetDST(dst []byte) []byte
	Identifier() hash.Identifier
}

// HashToRistretto allows hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
type HashToRistretto struct {
	Expander
	//originalDST []byte
	//dst         []byte
}

// New returns a newly instantiated HashToRistretto structure.
func New(id hash.Identifier) *HashToRistretto {
	h := &HashToRistretto{}
	switch id.Extensible() {
	case true:
		h.Expander = &XOF{id.(hash.Extensible)}
	case false:
		h.Expander = &XMD{id.(hash.Hashing)}
	}

	//h.originalDST = dst
	//h.dst = h.vetDST(dst)

	return h
}

// Expand expands the input by hashing using the expandMessageXMD or expandMessageXOF functions from hash-to-curve.
func (h *HashToRistretto) Expand(input, dst []byte, length int) []byte {
	// todo bring this back after testing
	//if len(h.dst) < group.DstRecommendedMinLength {
	//	if len(h.dst) == group.DstMinLength {
	//		panic(errZeroLenDST)
	//	}

	//	panic(errShortDST)
	//}

	// todo: what happens when input is nil ?
	return h.expandMessage(input, dst, length)
}

// GetOriginalDST returns the DST as given as input on instantiating of h.
// If the DST was too long, then it has been hashed afterwards in setDST. This function returns the unmodified DST.
//func (h *HashToRistretto) GetOriginalDST() string {
//	return string(h.originalDST)
//}

func msgPrime(h hash.Identifier, input, dst []byte, length int) []byte {
	lib := encoding.I2OSP(length, 2)
	dstPrime := dstPrime(dst)

	if h.Extensible() {
		return utils.Concatenate(0, input, lib, dstPrime)
	}

	zPad := make([]byte, h.BlockSize())
	zeroByte := []byte{0}

	return utils.Concatenate(0, zPad, input, lib, zeroByte, dstPrime)
}
