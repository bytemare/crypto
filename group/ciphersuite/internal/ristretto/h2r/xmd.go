// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"fmt"
	"math"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
)

func (h *HashToRistretto) dstPrime() []byte {
	return append(h.dst, byte(len(h.dst)))
}

func (h *HashToRistretto) msgPrime(input []byte, length int) []byte {
	lib := encoding.I2OSP(length, 2)
	dstPrime := h.dstPrime()

	if h.Extensible() {
		return utils.Concatenate(0, input, lib, dstPrime)
	}

	zPad := make([]byte, h.Hash.BlockSize())
	zeroByte := []byte{0}

	return utils.Concatenate(0, zPad, input, lib, zeroByte, dstPrime)
}

// expandMessageXMD implements https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-09.html#name-expand_message_xmd
func (h *HashToRistretto) expandMessageXMD(input []byte, length int) []byte {
	b := h.Hash.OutputSize()
	blockSize := h.Hash.BlockSize()

	ell := math.Ceil(float64(length / b))
	if ell > 255 {
		panic(fmt.Errorf("ell is > 255, i.e. the hash function's output length is too low: %d/%d", b, length))
	}

	dstPrime := h.dstPrime()
	zPad := make([]byte, blockSize)
	lib := encoding.I2OSP(length, 2)
	zeroByte := []byte{0}

	// Hash to b0
	b0 := h.Hash.Hash(b, zPad, input, lib, zeroByte, dstPrime)

	// Hash to b1
	b1 := h.Hash.Hash(b, b0, []byte{1}, dstPrime)

	// ell < 2 means the hash function's output length is sufficient
	if ell < 2 {
		return b1[0:length]
	}

	// Only if we need to expand the hash output, we keep on hashing
	return h.xmd(b0, b1, dstPrime, uint(ell), length)
}

// xmd expands the message digest until it reaches the desirable length.
func (h *HashToRistretto) xmd(b0, b1, dstPrime []byte, ell uint, length int) []byte {
	uniformBytes := make([]byte, 0, length)
	uniformBytes = append(uniformBytes, b1...)
	bi := make([]byte, len(b1))
	copy(bi, b1)

	for i := uint(2); i <= ell; i++ {
		xor := xorSlices(bi, b0)
		bi = h.Hash.Hash(0, xor, []byte{byte(i)}, dstPrime)
		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[0:length]
}

// xorSlices xors the two byte slices byte by byte, and returns a new buffer containing the result.
// Both slices must be of same length.
func xorSlices(bi, b0 []byte) []byte {
	for i := range bi {
		bi[i] ^= b0[i]
	}

	return bi
}
