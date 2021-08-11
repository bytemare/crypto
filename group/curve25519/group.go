// Package curve25519 implements a prime-order group over Curve25519 with hash-to-curve.
package curve25519

import (
	"crypto"

	"filippo.io/edwards25519"

	"github.com/bytemare/cryptotools/group/hash2curve"
	"github.com/bytemare/cryptotools/group/internal"
)

// H2C represents the hash-to-curve string identifier.
const H2C = "curve25519_XMD:SHA-512_ELL2_RO_"

// Curve25519Sha512 represents the Curve25519 group. It exposes a prime-order group API with hash-to-curve operations.
type Curve25519Sha512 struct{}

// NewScalar returns a new, empty, scalar.
func (c Curve25519Sha512) NewScalar() internal.Scalar {
	return newScalar()
}

// ElementLength returns the byte size of an encoded element.
func (c Curve25519Sha512) ElementLength() int {
	return canonicalEncodingLength
}

// NewElement returns a new, empty, element.
func (c Curve25519Sha512) NewElement() internal.Point {
	return newPoint()
}

// Identity returns the group's identity element.
func (c Curve25519Sha512) Identity() internal.Point {
	return newPoint()
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (c Curve25519Sha512) HashToGroup(input, dst []byte) internal.Point {
	return &Element{hash2curve.HashToEdwards25519(input, dst)}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (c Curve25519Sha512) HashToScalar(input, dst []byte) internal.Scalar {
	sc := hash2curve.HashToScalarXMD(crypto.SHA512, input, dst, canonicalEncodingLength)

	s, err := edwards25519.NewScalar().SetUniformBytes(sc)
	if err != nil {
		panic(err)
	}

	return &Scalar{s}
}

// Base returns the group's base point a.k.a. canonical generator.
func (c Curve25519Sha512) Base() internal.Point {
	return &Element{edwards25519.NewGeneratorPoint()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (c Curve25519Sha512) MultBytes(s, e []byte) (internal.Point, error) {
	sc, err := c.NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	el, err := c.NewElement().Decode(e)
	if err != nil {
		return nil, err
	}

	return el.Mult(sc), nil
}
