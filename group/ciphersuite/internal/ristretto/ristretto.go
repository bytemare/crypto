// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal/ristretto/h2r"
	"github.com/gtank/ristretto255"
)

const ristrettoInputLength = 64

// NewScalar returns a new, empty, scalar.
func NewScalar() group.Scalar {
	return &Scalar{ristretto255.NewScalar()}
}

// ElementLength returns the byte size of an encoded element.
func ElementLength() int {
	return canonicalEncodingLength
}

// NewElement returns a new, empty, element.
func NewElement() group.Element {
	return &Element{ristretto255.NewElement()}
}

// Identity returns the group's identity element.
func Identity() group.Element {
	return &Element{ristretto255.NewElement().Zero()}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func HashToGroup(input, dst []byte) group.Element {
	uniform := h2r.ExpandMessage(input, dst, ristrettoInputLength)

	return &Element{ristretto255.NewElement().FromUniformBytes(uniform)}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func HashToScalar(input, dst []byte) group.Scalar {
	uniform := h2r.ExpandMessage(input, dst, ristrettoInputLength)

	return &Scalar{ristretto255.NewScalar().FromUniformBytes(uniform)}
}

// Base returns Ristretto255's base point a.k.a. canonical generator.
func Base() group.Element {
	return &Element{ristretto255.NewElement().Base()}
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
