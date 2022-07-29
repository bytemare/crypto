// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist_test

import (
	"bytes"
	"testing"
)

func TestScalarArithmetic(t *testing.T) {
	for _, group := range groups {
		t.Run(group.Ciphersuite(), func(t *testing.T) {
			// Test Addition and Substraction
			s := group.NewScalar().Random()
			a := s.Add(s)
			r := a.Sub(s)
			if !bytes.Equal(r.Bytes(), s.Bytes()) {
				t.Fatal("not equal")
			}

			// Test Multiplication and inversion
			s = group.NewScalar().Random()
			sqr := s.Mult(s)
			i := s.Invert().Mult(sqr)
			if !bytes.Equal(i.Bytes(), s.Bytes()) {
				t.Fatal("not equal")
			}
		})
	}
}
