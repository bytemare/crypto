// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"math"
)

type XOF struct {
	hash.Extensible
}

// expandMessageXOF implements https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-09.html#name-expand_message_xof
func (x *XOF) expandMessage(input, dst []byte, length int) []byte {
	len2o := encoding.I2OSP(length, 2)
	dstLen2o := encoding.I2OSP(len(dst), 1)

	return x.Get().Hash(length, input, len2o, dst, dstLen2o)
}

func (x *XOF) vetDST(dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	ext := append([]byte(dstLongPrefix), dst...)

	size := x.MinOutputSize()

	k := x.SecurityLevel()
	size = int(math.Ceil(float64(2 * k / 8)))

	return x.Get().Hash(size, ext)
}
