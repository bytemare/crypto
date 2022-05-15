// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package nistec wraps the
package nistec

import (
	"filippo.io/nistec"
)

type MyP256Point struct {
	point *nistec.P256Point
}

func NewMyP256Point() *MyP256Point {
	return &MyP256Point{point: nistec.NewP256Point()}
}

// Add sets q = p1 + p2, and returns q. The points may overlap.
func (p *MyP256Point) Add(p1, p2 *MyP256Point) *MyP256Point {
	p.point.Add(p1.point, p2.point)

	return p
}

// Double sets q = p + p, and returns q. The points may overlap.
func (p *MyP256Point) Double(p1 *MyP256Point) *MyP256Point {
	p.point.Double(p1.point)
	return p
}

// ScalarBaseMult sets r = scalar * generator, where scalar is a 32-byte big
// endian value, and returns r. If scalar is not 32 bytes long, ScalarBaseMult
// returns an error and the receiver is unchanged.
func (p *MyP256Point) ScalarBaseMult(scalar []byte) (*MyP256Point, error) {
	if _, err := p.point.ScalarBaseMult(scalar); err != nil {
		return nil, err
	}

	return p, nil
}

// ScalarMult sets r = scalar * q, where scalar is a 32-byte big endian value,
// and returns r. If scalar is not 32 bytes long, ScalarBaseMult returns an
// error and the receiver is unchanged.
func (p *MyP256Point) ScalarMult(q *MyP256Point, scalar []byte) (*MyP256Point, error) {
	if _, err := p.point.ScalarMult(q.point, scalar); err != nil {
		return nil, err
	}

	return p, nil
}

// Select sets q to p1 if cond == 1, and to p2 if cond == 0.
func (p *MyP256Point) Select(p1, p2 *MyP256Point, cond int) *MyP256Point {
	p.point.Select(p1.point, p2.point, cond)

	return p
}

// Set sets p = q and returns p.
func (p *MyP256Point) Set(q *MyP256Point) *MyP256Point {
	p.point.Set(q.point)

	return p
}

// SetBytes sets p to the compressed, uncompressed, or infinity value encoded in
// b, as specified in SEC 1, Version 2.0, Section 2.3.4. If the point is not on
// the curve, it returns nil and an error, and the receiver is unchanged.
// Otherwise, it returns p.
func (p *MyP256Point) SetBytes(b []byte) (*MyP256Point, error) {
	if _, err := p.point.SetBytes(b); err != nil {
		panic(err)
	}

	return p, nil
}

// SetGenerator sets p to the canonical generator and returns p.
func (p *MyP256Point) SetGenerator() *MyP256Point {
	p.point.SetGenerator()

	return p
}

// Bytes returns the compressed or infinity encoding of p, as
// specified in SEC 1, Version 2.0, Section 2.3.3. Note that the encoding of the
// point at infinity is shorter than all other encodings.
func (p *MyP256Point) Bytes() []byte {
	return p.point.BytesCompressed()
}
