package hash2curve

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash"
)

func HashToFieldXOF(id hash.Extendable, input, dst []byte, count, ext, securityLength int, modulo *big.Int) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXOF(id, input, dst, expLength)

	res := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func HashToFieldXMD(id crypto.Hash, input, dst []byte, count, ext, securityLength int, modulo *big.Int) []*big.Int {
	expLength := count * ext * securityLength // elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	res := make([]*big.Int, count)

	for i := 0; i < count; i++ {
		offset := i * securityLength
		res[i] = reduce(uniform[offset:offset+securityLength], modulo)
	}

	return res
}

func reduce(input []byte, modulo *big.Int) *big.Int {
	/*
		Interpret the input as a big-endian encoded unsigned integer of the field, and reduce it modulo the prime.
	*/
	i := new(big.Int).SetBytes(input)
	i.Mod(i, modulo)

	return i
}
