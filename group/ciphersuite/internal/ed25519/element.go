package ed25519

import (
	"filippo.io/edwards25519"
	"fmt"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal"
)

type Element struct {
	element *edwards25519.Point
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element group.Element) group.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Add(e.element, ele.element)}
}

// Sub returns the difference between the Elements, and does not change the receiver.
func (e *Element) Sub(element group.Element) group.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Subtract(e.element, ele.element)}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Mult(scalar group.Scalar) group.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().ScalarMult(sc.scalar, e.element)}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (e *Element) InvertMult(scalar group.Scalar) group.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return e.Mult(scalar.Invert())
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() group.Element {
	n := edwards25519.NewIdentityPoint()
	if _, err := n.SetBytes(e.element.Bytes()); err != nil {
		panic(err)
	}

	return &Element{element: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (group.Element, error) {
	if len(in) == 0 {
		return nil, internal.ErrParamNilPoint
	}

	p := edwards25519.NewIdentityPoint()
	if _, err := p.SetBytes(in); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	return e, nil
}

// Bytes returns the compressed byte encoding of the element.
func (e *Element) Bytes() []byte {
	return e.element.Bytes()
}
