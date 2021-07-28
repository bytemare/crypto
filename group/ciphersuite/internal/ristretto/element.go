// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import (
	"fmt"
	"github.com/bytemare/cryptotools/group/ciphersuite/internal"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/cryptotools/group"
)

// Element implements the Element interface for the Ristretto255 group element.
type Element struct {
	element *ristretto255.Element
}

// Add adds the argument to the receiver, sets the receiver to the result and returns it.
func (e *Element) Add(element group.Element) group.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{ristretto255.NewElement().Add(e.element, ele.element)}
}

// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (e *Element) Sub(element group.Element) group.Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{ristretto255.NewElement().Subtract(e.element, ele.element)}
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

	return &Element{ristretto255.NewElement().ScalarMult(sc.scalar, e.element)}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (e *Element) InvertMult(scalar group.Scalar) group.Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return e.Mult(scalar.Invert())
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

	return &Element{element: n}
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
		return nil, internal.ErrParamNilPoint
	}

	e := ristretto255.NewElement()
	if err := e.Decode(element); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	return e, nil
}
