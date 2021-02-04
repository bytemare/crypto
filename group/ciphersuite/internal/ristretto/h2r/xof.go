// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"github.com/bytemare/cryptotools/encoding"
)

// expandMessageXOF implements https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-09.html#name-expand_message_xof
func (h *HashToRistretto) expandMessageXOF(input []byte, length int) []byte {
	len2o := encoding.I2OSP(length, 2)
	dstLen2o := encoding.I2OSP(len(h.dst), 1)

	return h.Hash.Hash(length, input, len2o, h.dst, dstLen2o)
}
