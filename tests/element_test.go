// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"bytes"
	"testing"

	"github.com/bytemare/crypto"
)

func TestPoint_Decode(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		element := group.id.Base().Multiply(group.id.NewScalar().Random())
		encoded := element.Bytes()

		decoded, err := group.id.NewElement().Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if element.Equal(decoded) != 1 {
			t.Fatal("expected equality")
		}

		if !bytes.Equal(encoded, decoded.Bytes()) {
			t.Fatal("expected equality when en/decoding element")
		}

		_, err = group.id.NewElement().Decode(nil)
		if err == nil {
			t.Fatal("expected error on nil input")
		}
	})
}

func TestPoint_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testPointArithmetic(t, group.id)
	})
}

func testPointArithmetic(t *testing.T, g crypto.Group) {
	// Test Addition and Subtraction
	base := g.Base()

	double := base.Add(base)
	if double.Equal(base.Double()) != 1 {
		t.Fatal("expected equality")
	}

	if base.Add(nil).Equal(base) != 1 {
		t.Fatal("expected equality")
	}

	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal("expected equality")
	}

	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal("expected equality")
	}

	scalar := g.NewScalar().Random()
	for scalar.IsZero() {
		scalar = g.NewScalar().Random()
	}

	m := base.Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	scalar.Zero()

	m = base.Multiply(scalar)
	if !m.IsIdentity() {
		t.Fatal("expected identity")
	}

	scalar.Random()
	base = g.Base()
	m = base.Multiply(scalar)

	m2, err := g.MultBytes(scalar.Bytes(), base.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(m.Bytes(), m2.Bytes()) {
		t.Fatal("expected equality")
	}

	base = g.Base()
	inv := m.Multiply(scalar.Invert())

	if inv.Equal(base) != 1 {
		t.Fatal("expected equality")
	}

	// Test identity
	id := g.NewElement()
	if !id.IsIdentity() {
		t.Fatal("expected identity")
	}

	base = g.NewElement().Base()
	if id.Equal(base.Subtract(base)) != 1 {
		t.Fatal("expected identity")
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal("expected identity")
	}

	if id.Equal(base.Multiply(scalar.Zero())) != 1 {
		t.Fatal("expected identity")
	}

	base2 = base.Add(base.Negate())
	if id.Equal(base2) != 1 {
		t.Fatal("expected identity")
	}
}
