// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"crypto"

	"filippo.io/edwards25519"

	"github.com/bytemare/cryptotools/group/hash2curve"
	"github.com/bytemare/cryptotools/group/internal"
)

// H2C represents the hash-to-curve string identifier.
const H2C = "edwards25519_XMD:SHA-512_ELL2_RO_"

// Edwards25519Sha512 represents the Edwards25519 group. It exposes a prime-order group API with hash-to-curve operations.
type Edwards25519Sha512 struct{}

// NewScalar returns a new, empty, scalar.
func (e Edwards25519Sha512) NewScalar() internal.Scalar {
	return &Scalar{edwards25519.NewScalar()}
}

// ElementLength returns the byte size of an encoded element.
func (e Edwards25519Sha512) ElementLength() int {
	return canonicalEncodingLength
}

// NewElement returns a new, empty, element.
func (e Edwards25519Sha512) NewElement() internal.Point {
	return &Element{edwards25519.NewIdentityPoint()}
}

// Identity returns the group's identity element.
func (e Edwards25519Sha512) Identity() internal.Point {
	return &Element{edwards25519.NewIdentityPoint()}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (e Edwards25519Sha512) HashToGroup(input, dst []byte) internal.Point {
	return &Element{hash2curve.HashToEdwards25519(input, dst)}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (e Edwards25519Sha512) HashToScalar(input, dst []byte) internal.Scalar {
	sc := hash2curve.HashToScalarXMD(crypto.SHA512, input, dst, canonicalEncodingLength)

	s, err := edwards25519.NewScalar().SetUniformBytes(sc)
	if err != nil {
		panic(err)
	}

	return &Scalar{s}
}

// Base returns group's base point a.k.a. canonical generator.
func (e Edwards25519Sha512) Base() internal.Point {
	return &Element{edwards25519.NewGeneratorPoint()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (e Edwards25519Sha512) MultBytes(s, e0 []byte) (internal.Point, error) {
	sc, err := e.NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	e1, err := e.NewElement().Decode(e0)
	if err != nil {
		return nil, err
	}

	return e1.Mult(sc), nil
}
