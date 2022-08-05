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

	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/internal"
)

// Element implements the Element interface for the Ristretto255 group element.
type Element struct {
	element *ristretto255.Element
}

func checkElement(element internal.Element) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

func (e *Element) Base() internal.Element {
	e.element.Base()
	return e
}

func (e *Element) Identity() internal.Element {
	e.element.Zero()
	return e
}

func (e *Element) set(element *Element) *Element {
	*e = *element
	return e
}

// Set sets the receiver to the argument, and returns the receiver.
func (e *Element) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.set(nil)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return e.set(ec)
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Add(e.element, ec.element)

	return e
}

func (e *Element) Double() internal.Element {
	e.element.Add(e.element, e.element)
	return e
}

func (e *Element) Negate() internal.Element {
	e.element.Negate(e.element)
	return e
}

// Subtract subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (e *Element) Subtract(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Subtract(e.element, ec.element)

	return e
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		e.element = ristretto255.NewElement()
		return e
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	e.element.ScalarMult(sc.scalar, e.element)

	return e
}

func (e *Element) Equal(element internal.Element) int {
	ec := checkElement(element)
	return e.element.Equal(ec.element)
}

// IsIdentity returns whether the element is the group's identity element.
func (e *Element) IsIdentity() bool {
	id := ristretto255.NewElement().Zero()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() internal.Element {
	n := ristretto255.NewElement()
	if err := n.Decode(e.element.Encode(nil)); err != nil {
		panic(err)
	}

	return &Element{element: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (internal.Element, error) {
	el, err := decodeElement(in)
	if err != nil {
		return nil, err
	}

	// superfluous identity check
	if el.Equal(ristretto255.NewElement().Zero()) == 1 {
		return nil, internal.ErrIdentity
	}

	e.element = el

	return e, nil
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.element.Encode(nil)
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

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	_, err := e.Decode(data)
	return err
}
