// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/crypto"
)

const consideredAvailableFmt = "%v is considered available when it must not"

func TestAvailability(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if !group.id.Available() {
			t.Errorf("'%s' is not available, but should be", group.id.String())
		}
	})
}

func TestNonAvailability(t *testing.T) {
	oob := crypto.Group(0)
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}

	d := crypto.Group(2) // decaf448
	if d.Available() {
		t.Errorf(consideredAvailableFmt, d)
	}

	oob = crypto.Edwards25519Sha512 + 1
	if oob.Available() {
		t.Errorf(consideredAvailableFmt, oob)
	}
}

func TestGroup_Base(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if hex.EncodeToString(group.id.Base().Encode()) != group.basePoint {
			t.Fatalf("Got wrong base element %s", hex.EncodeToString(group.id.Base().Encode()))
		}
	})
}

func TestDST(t *testing.T) {
	app := "app"
	version := uint8(1)
	tests := map[crypto.Group]string{
		crypto.Ristretto255Sha512: app + "-V01-CS01-",
		crypto.P256Sha256:         app + "-V01-CS03-",
		crypto.P384Sha384:         app + "-V01-CS04-",
		crypto.P521Sha512:         app + "-V01-CS05-",
		crypto.Edwards25519Sha512: app + "-V01-CS06-",
	}

	testAll(t, func(t2 *testing.T, group *testGroup) {
		res := string(group.id.MakeDST(app, version))
		test := tests[group.id] + group.h2c
		if res != test {
			t.Errorf("Wrong DST. want %q, got %q", res, test)
		}
	})
}

func TestGroup_String(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		res := group.id.String()
		ref := group.h2c
		if res != ref {
			t.Errorf("Wrong DST. want %q, got %q", ref, res)
		}
	})
}

func TestGroup_NewScalar(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		s := group.id.NewScalar().Encode()
		for _, b := range s {
			if b != 0 {
				t.Fatalf("expected zero scalar, but got %v", hex.EncodeToString(s))
			}
		}
	})
}

func TestGroup_NewElement(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		e := hex.EncodeToString(group.id.NewElement().Encode())
		ref := group.identity

		if e != ref {
			t.Fatalf("expected identity element %v, but got %v", ref, e)
		}
	})
}

func TestGroup_ScalarLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if int(group.id.ScalarLength()) != group.scalarLength {
			t.Fatalf("expected encoded scalar length %d, but got %d", group.scalarLength, group.id.ScalarLength())
		}
	})
}

func TestGroup_ElementLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *testGroup) {
		if int(group.id.ElementLength()) != group.elementLength {
			t.Fatalf("expected encoded element length %d, but got %d", group.elementLength, group.id.ElementLength())
		}
	})
}
