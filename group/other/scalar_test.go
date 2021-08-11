// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package other

import (
	"testing"

	"github.com/armfazh/h2c-go-ref"
	"github.com/stretchr/testify/assert"
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

	assert.True(t, s3.Equal(s.(*Scalar)))
}

func TestScalarArithmetic(t *testing.T) {
	g := New(h2c.P256_XMDSHA256_SSWU_RO_)

	// Test Addition and Substraction
	s := g.NewScalar().Random()
	assert.Equal(t, s.Add(nil).Bytes(), s.Bytes())
	a := s.Add(s)
	assert.Equal(t, a.Sub(nil).Bytes(), a.Bytes())
	r := a.Sub(s)
	assert.Equal(t, r.Bytes(), s.Bytes())

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	m := s.Mult(s)
	i := s.Invert().Mult(m)
	// i := m.Mult(s.Invert())
	assert.Equal(t, i.Bytes(), s.Bytes())
}
