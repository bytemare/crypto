// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package other

import (
	"bytes"
	"testing"

	"github.com/armfazh/h2c-go-ref"
)

func TestScalarEncoding(t *testing.T) {
	h2p, err := h2c.P256_XMDSHA256_SSWU_RO_.Get([]byte("dst"))
	if err != nil {
		t.Fatal(err)
	}

	f := h2p.GetHashToScalar().GetScalarField()

	s := scalar(f).Random()

	enc := s.Bytes()
	s2, _ := scalar(f).Decode(enc)

	s3 := s2.(*Scalar)

	if !s3.Equal(s.(*Scalar)) {
		t.Fatal("expected assertion to be true")
	}
}

func TestScalarArithmetic(t *testing.T) {
	g := New(h2c.P256_XMDSHA256_SSWU_RO_)

	// Test Addition and Substraction
	s := g.NewScalar().Random()
	if !bytes.Equal(s.Add(nil).Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}
	a := s.Add(s)
	if !bytes.Equal(a.Sub(nil).Bytes(), a.Bytes()) {
		t.Fatal("not equal")
	}
	r := a.Sub(s)
	if !bytes.Equal(r.Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	m := s.Mult(s)
	i := s.Invert().Mult(m)
	// i := m.Mult(s.Invert())
	if !bytes.Equal(i.Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}
}
