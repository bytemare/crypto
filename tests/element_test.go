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
	testAllGroups(t, func(t2 *testing.T, group *testGroup) {
		element := group.id.Base().Multiply(group.id.NewScalar().Random())
		encoded := element.Encode()

		decoded := group.id.NewElement()
		if err := decoded.Decode(encoded); err != nil {
			t.Fatal(err)
		}

		if element.Equal(decoded) != 1 {
			t.Fatal("expected equality")
		}

		if !bytes.Equal(encoded, decoded.Encode()) {
			t.Fatal("expected equality when en/decoding element")
		}

		if err := group.id.NewElement().Decode(nil); err == nil {
			t.Fatal("expected error on nil input")
		}
	})
}

func TestPoint_Arithmetic(t *testing.T) {
	testAllGroups(t, func(t2 *testing.T, group *testGroup) {
		elementTestAdd(t, group.id)
		elementTestDouble(t, group.id)
		elementTestSubstract(t, group.id)
		elementTestMultiply(t, group.id)
		elementTestMultbytes(t, group.id)
		elementTestInversion(t, group.id)
		elementTestIdentity(t, group.id)
	})
}

func elementTestAdd(t *testing.T, g crypto.Group) {
	// Verify whether add yields the same element when given nil
	base := g.Base()
	cpy := base.Copy()
	if cpy.Add(nil).Equal(base) != 1 {
		t.Fatal("expected equality")
	}
}

func elementTestDouble(t *testing.T, g crypto.Group) {
	// Verify whether double works like adding
	base := g.Base()

	double := g.Base().Add(base)
	if double.Equal(base.Double()) != 1 {
		t.Fatal("expected equality")
	}
}

func elementTestSubstract(t *testing.T, g crypto.Group) {
	base := g.Base()

	// Verify whether subtrating yields the same element when given nil.
	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal("expected equality")
	}

	// Verify whether subtracting and then adding yields the same element.
	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal("expected equality")
	}
}

func elementTestMultiply(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar().Random()

	// Random scalar mult must not yield identity
	m := g.Base().Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	// base = base * 1
	base := g.Base()
	if base.Equal(g.Base().Multiply(scalar.One())) != 1 {
		t.Fatal("expected equality")
	}

	// base * 0 = id
	if !g.Base().Multiply(scalar.Zero()).IsIdentity() {
		t.Fatal("expected identity")
	}

	// base * nil = id
	if !g.Base().Multiply(nil).IsIdentity() {
		t.Fatal("expected identity")
	}
}

func elementTestMultbytes(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar().Random()
	base := g.Base()
	m := g.Base().Multiply(scalar)

	m2, err := g.MultBytes(scalar.Encode(), base.Encode())
	if err != nil {
		t.Fatal(err)
	}

	if m.Equal(m2) != 1 {
		t.Fatal("expected equality")
	}
}

func elementTestInversion(t *testing.T, g crypto.Group) {
	scalar := g.NewScalar().Random()
	base := g.Base()
	m := g.Base().Multiply(scalar)
	inv := m.Multiply(scalar.Invert())

	if inv.Equal(base) != 1 {
		t.Fatal("expected equality")
	}
}

func elementTestIdentity(t *testing.T, g crypto.Group) {
	id := g.NewElement()
	if !id.IsIdentity() {
		t.Fatal("expected identity")
	}

	base := g.Base()
	if id.Equal(base.Subtract(base)) != 1 {
		t.Fatal("expected identity")
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal("expected identity")
	}

	if id.Equal(base.Multiply(g.NewScalar().Zero())) != 1 {
		t.Fatal("expected identity")
	}

	base = g.Base()
	base.Add(base.Negate())
	if id.Equal(base) != 1 {
		t.Fatal("expected identity")
	}
}
