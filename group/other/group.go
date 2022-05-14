// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package other wraps a hash-to-curve implementation and exposes functions for operations on points and scalars.
package other

import (
	"errors"

	H2C "github.com/armfazh/h2c-go-ref"

	"github.com/bytemare/crypto/group/internal"
)

// Hash2Curve implements the Group interface to Hash-to-Curve primitives.
type Hash2Curve struct {
	suite H2C.SuiteID
}

// New returns a pointer to a Hash2Curve structure instantiated for the given Hash-to-Curve identifier.
// and the domain separation tag.
func New(id H2C.SuiteID) *Hash2Curve {
	h, err := id.Get(nil)
	if err != nil {
		panic(err)
	}

	if !h.IsRandomOracle() {
		panic(errParamNotRandomOracle)
	}

	return &Hash2Curve{id}
}

// NewScalar returns a new, empty, scalar.
func (h *Hash2Curve) NewScalar() internal.Scalar {
	h2 := getH2C(h.suite, nil)

	return scalar(h2.GetHashToScalar().GetScalarField())
}

// ElementLength returns the byte size of an encoded element.
func (h *Hash2Curve) ElementLength() uint {
	h2 := getH2C(h.suite, nil)

	return pointLen(h2.GetCurve().Field().BitLen())
}

// NewElement returns the identity point (point at infinity).
func (h *Hash2Curve) NewElement() internal.Element {
	h2 := getH2C(h.suite, nil)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      curves[h.suite].New(h2.GetCurve()).Identity(),
	}
}

// Identity returns the group's identity element.
func (h *Hash2Curve) Identity() internal.Element {
	h2 := getH2C(h.suite, nil)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      h2.GetCurve().Identity(),
	}
}

const (
	minLength            = 0
	recommendedMinLength = 16
)

var errZeroLenDST = errors.New("zero-length DST")

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	}
}

func getH2C(id H2C.SuiteID, dst []byte) H2C.HashToPoint {
	h, err := id.Get(dst)
	if err != nil {
		panic(err)
	}

	if !h.IsRandomOracle() {
		panic(errParamNotRandomOracle)
	}

	return h
}

func getCurve(id H2C.SuiteID) *curve {
	h2 := getH2C(id, nil)
	return curves[id].New(h2.GetCurve())
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the Group.
func (h *Hash2Curve) HashToGroup(input, dst []byte) internal.Element {
	checkDST(dst)
	h2 := getH2C(h.suite, dst)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      h2.Hash(input),
	}
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (h *Hash2Curve) EncodeToGroup(input, dst []byte) internal.Element {
	var id H2C.SuiteID

	switch h.suite {
	case H2C.P256_XMDSHA256_SSWU_RO_:
		id = H2C.P256_XMDSHA256_SSWU_NU_
	case H2C.P384_XMDSHA384_SSWU_RO_:
		id = H2C.P384_XMDSHA384_SSWU_NU_
	case H2C.P521_XMDSHA512_SSWU_RO_:
		id = H2C.P521_XMDSHA512_SSWU_NU_
	case H2C.Curve448_XOFSHAKE256_ELL2_RO_:
		id = H2C.Curve448_XOFSHAKE256_ELL2_NU_
	case H2C.Edwards448_XOFSHAKE256_ELL2_RO_:
		id = H2C.Edwards448_XOFSHAKE256_ELL2_NU_
	case H2C.Secp256k1_XMDSHA256_SSWU_RO_:
		id = H2C.Secp256k1_XMDSHA256_SSWU_NU_
	default:
		panic("suite not referenced")
	}

	h2 := getH2C(id, dst)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      h2.Hash(input),
	}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (h *Hash2Curve) HashToScalar(input, dst []byte) internal.Scalar {
	checkDST(dst)
	h2 := getH2C(h.suite, dst)

	return &Scalar{
		s: h2.GetHashToScalar().Hash(input),
		f: h2.GetHashToScalar().GetScalarField(),
	}
}

// Base returns the group's base point a.k.a. canonical generator.
func (h *Hash2Curve) Base() internal.Element {
	h2 := getH2C(h.suite, nil)

	return &Point{
		Hash2Curve: h,
		curve:      getCurve(h.suite),
		point:      curves[h.suite].New(h2.GetCurve()).base,
	}
}

// MultBytes allows []byte encodings of a scalar and an element of the Group to be multiplied.
func (h *Hash2Curve) MultBytes(scalar, element []byte) (internal.Element, error) {
	s, err := h.NewScalar().Decode(scalar)
	if err != nil {
		return nil, err
	}

	e, err := h.NewElement().Decode(element)
	if err != nil {
		return nil, err
	}

	return e.Mult(s), nil
}
