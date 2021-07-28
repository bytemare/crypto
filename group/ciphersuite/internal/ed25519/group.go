package ed25519

import (
	"filippo.io/edwards25519"
	"github.com/bytemare/hash2curve"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
)

const String = "edwards25519_XMD:SHA-512_ELL2_RO_"

// NewScalar returns a new, empty, scalar.
func NewScalar() group.Scalar {
	return &Scalar{edwards25519.NewScalar()}
}

// ElementLength returns the byte size of an encoded element.
func ElementLength() int {
	return canonicalEncodingLength
}

// NewElement returns a new, empty, element.
func NewElement() group.Element {
	return &Element{edwards25519.NewIdentityPoint()}
}

// Identity returns the group's identity element.
func Identity() group.Element {
	return &Element{edwards25519.NewIdentityPoint()}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func HashToGroup(input, dst []byte) group.Element {
	uniform := hash2curve.ExpandMessage(hash.SHA512, input, dst, inputLength)

	p, err := edwards25519.NewIdentityPoint().SetBytes(uniform)
	if err != nil {
		panic(err)
	}

	return &Element{p}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func HashToScalar(input, dst []byte) group.Scalar {
	uniform := hash2curve.ExpandMessage(hash.SHA512, input, dst, inputLength)

	s, err := edwards25519.NewScalar().SetUniformBytes(uniform)
	if err != nil {
		panic(err)
	}

	return &Scalar{s}
}

// Base returns Ristretto255's base point a.k.a. canonical generator.
func Base() group.Element {
	return &Element{edwards25519.NewGeneratorPoint()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func MultBytes(s, e []byte) (group.Element, error) {
	sc, err := NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	el, err := NewElement().Decode(e)
	if err != nil {
		return nil, err
	}

	return el.Mult(sc), nil
}
