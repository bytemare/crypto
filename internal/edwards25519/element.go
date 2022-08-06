// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"encoding/base64"
	"fmt"

	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

// Element represents an Edwards25519 point.
// It wraps an Edwards25519 implementation to leverage its optimized operations.
type Element struct {
	element edwards25519.Point
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
	e.element.Set(edwards25519.NewGeneratorPoint())
	return e
}

func (e *Element) Identity() internal.Element {
	e.element.Set(edwards25519.NewIdentityPoint())
	return e
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Add(&e.element, &ec.element)

	return e
}

func (e *Element) Double() internal.Element {
	return e.Add(e)
}

func (e *Element) Negate() internal.Element {
	e.element.Negate(&e.element)
	return e
}

// Subtract returns the difference between the Elements, and does not change the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	ec := checkElement(element)
	e.element.Subtract(&e.element, &ec.element)

	return e
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		e.element = *edwards25519.NewIdentityPoint()
		return e
	}

	sc := assert(scalar)
	e.element.ScalarMult(&sc.scalar, &e.element)

	return e
}

func (e *Element) Equal(element internal.Element) int {
	ec := checkElement(element)
	return e.element.Equal(&ec.element)
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return e.element.Equal(id) == 1
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

// Copy returns a copy of the element.
func (e *Element) Copy() internal.Element {
	n, err := edwards25519.NewIdentityPoint().SetBytes(e.element.Bytes())
	if err != nil {
		panic(err)
	}

	return &Element{element: *n}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.element.Bytes()
}

// Decode decodes the input and sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) error {
	if len(in) == 0 {
		return internal.ErrParamNilPoint
	}

	if _, err := e.element.SetBytes(in); err != nil {
		return fmt.Errorf("decoding element : %w", err)
	}

	if e.IsIdentity() {
		return internal.ErrIdentity
	}

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.element.Bytes(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}

// MarshalText implements the encoding.MarshalText interface.
func (e *Element) MarshalText() (text []byte, err error) {
	b := e.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.UnmarshalText interface.
func (e *Element) UnmarshalText(text []byte) error {
	eb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return e.Decode(eb)
	}

	return err
}
