// Package h2r provides hash-to-curve compatible hashing or arbitrary input into the Ristretto255 group.
package h2r

import (
	"fmt"
	"github.com/bytemare/cryptotools/hash"
	"math"

	"github.com/bytemare/cryptotools/encoding"
)

type XMD struct {
	hash.Hashing
}

func (x *XMD) Identifier() hash.Identifier {
	return x.Hashing
}

// expandMessageXMD implements https://www.ietf.org/id/draft-irtf-cfrg-hash-to-curve-09.html#name-expand_message_xmd
func (x *XMD) expandMessage(input, dst []byte, length int) []byte {
	h := x.Hashing.Get()
	b := h.OutputSize()
	blockSize := h.BlockSize()

	ell := math.Ceil(float64(length / b))
	if ell > 255 {
		panic(fmt.Errorf("ell is > 255, i.e. the hash function's output length is too low: %d/%d", b, length))
	}

	dstPrime := dstPrime(dst)
	zPad := make([]byte, blockSize)
	lib := encoding.I2OSP(length, 2)
	zeroByte := []byte{0}

	// Hash to b0
	b0 := h.Hash(zPad, input, lib, zeroByte, dstPrime)

	// Hash to b1
	b1 := h.Hash(b0, []byte{1}, dstPrime)

	// ell < 2 means the hash function's output length is sufficient
	if ell < 2 {
		return b1[0:length]
	}

	// Only if we need to expand the hash output, we keep on hashing
	return x.xmd(b0, b1, dstPrime, uint(ell), length)
}

func dstPrime(dst []byte) []byte {
	return append(dst, encoding.I2OSP(len(dst), 1)...)
}

// xmd expands the message digest until it reaches the desirable length.
func (x *XMD) xmd(b0, b1, dstPrime []byte, ell uint, length int) []byte {
	uniformBytes := make([]byte, 0, length)
	uniformBytes = append(uniformBytes, b1...)
	bi := make([]byte, len(b1))
	copy(bi, b1)

	for i := uint(2); i <= ell; i++ {
		xor := xorSlices(bi, b0)
		bi = x.Hash(xor, []byte{byte(i)}, dstPrime)
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

func (x *XMD) vetDST(dst []byte) []byte {
	if len(dst) <= dstMaxLength {
		return dst
	}

	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	return x.Hash([]byte(dstLongPrefix), dst)
}
