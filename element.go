// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package crypto exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package crypto

import "github.com/bytemare/crypto/internal"

// Element represents an element on the curve of the prime-order group.
type Element struct {
	internal.Element
}

func newPoint(p internal.Element) *Element {
	return &Element{p}
}

// Add returns the sum of the Points, and does not change the receiver.
func (p *Element) Add(element *Element) *Element {
	if element == nil {
		return &Element{p.Element.Copy()}
	}

	return &Element{p.Element.Add(element.Element)}
}

// Subtract returns the difference between the Points, and does not change the receiver.
func (p *Element) Subtract(element *Element) *Element {
	if element == nil {
		return &Element{p.Element.Copy()}
	}

	return &Element{p.Element.Subtract(element.Element)}
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar.
func (p *Element) Multiply(scalar *Scalar) *Element {
	if scalar == nil {
		return &Element{p.Element.Identity()}
	}

	return &Element{p.Element.Multiply(scalar.Scalar)}
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (p *Element) Equal(element *Element) int {
	if element == nil {
		return 0
	}

	return p.Element.Equal(element.Element)
}

// IsIdentity returns whether the element is the Group's identity element.
func (p *Element) IsIdentity() bool {
	return p.Element.IsIdentity()
}

// Copy returns a copy of the element.
func (p *Element) Copy() *Element {
	return &Element{p.Element.Copy()}
}

// Decode decodes the input and sets the current element to its value, and returns it.
func (p *Element) Decode(in []byte) (*Element, error) {
	q, err := p.Element.Decode(in)
	if err != nil {
		return nil, err
	}

	return &Element{q}, nil
}

// Bytes returns the compressed byte encoding of the element.
func (p *Element) Bytes() []byte {
	return p.Element.Encode()
}

func (p *Element) Double() *Element {
	return &Element{p.Element.Double()}
}

func (p *Element) Base() *Element {
	return &Element{p.Element.Base()}
}

func (p *Element) Identity() *Element {
	return &Element{p.Element.Identity()}
}

func (p *Element) Negate() *Element {
	return &Element{p.Element.Negate()}
}
