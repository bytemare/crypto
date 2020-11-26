// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import (
	"fmt"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/cryptotools/hashtogroup/internal/ristretto/h2r"
)

// Element implements the Element interface for the Ristretto255 group element.
type Element struct {
	*h2r.HashToRistretto
	element *ristretto255.Element
}

// Add adds the argument to the receiver, sets the receiver to the result and returns it.
func (e *Element) Add(element group.Element) group.Element {
	if element == nil {
		panic(errParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(errCastElement)
	}

	e.element = e.element.Add(e.element, ele.element)

	return e
}

// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (e *Element) Sub(element group.Element) group.Element {
	if element == nil {
		panic(errParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(errCastElement)
	}

	e.element = e.element.Subtract(e.element, ele.element)

	return e
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Mult(s group.Scalar) group.Element {
	if s == nil {
		panic(errParamNilScalar)
	}

	sc, ok := s.(*Scalar)
	if !ok {
		panic(errCastElement)
	}

	return &Element{
		HashToRistretto: e.HashToRistretto,
		element:         ristretto255.NewElement().ScalarMult(sc.Scalar, e.element),
	}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (e *Element) InvertMult(s group.Scalar) group.Element {
	if s == nil {
		panic(errParamNilScalar)
	}

	return e.Mult(s.Invert())
}

// IsIdentity returns whether the element is the group's identity element.
func (e *Element) IsIdentity() bool {
	id := ristretto255.NewElement().Zero()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() group.Element {
	n := ristretto255.NewElement()
	if err := n.Decode(e.element.Encode(nil)); err != nil {
		panic(err)
	}

	return &Element{
		HashToRistretto: e.HashToRistretto,
		element:         n,
	}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (group.Element, error) {
	el, err := decodeElement(in)
	if err != nil {
		return nil, err
	}

	e.element = el

	return e, nil
}

// Bytes returns the compressed byte encoding of the element.
func (e *Element) Bytes() []byte {
	return e.element.Encode(nil)
}

// Base returns the group's base point.
func (e *Element) Base() group.Element {
	e.element = ristretto255.NewElement().Base()
	return e
}

func decodeElement(element []byte) (*ristretto255.Element, error) {
	if len(element) == 0 {
		return nil, errParamNilPoint
	}

	e := ristretto255.NewElement()
	if err := e.Decode(element); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	return e, nil
}
