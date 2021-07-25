// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	"testing"
)

func TestEncode_GobFail(t *testing.T) {
	// Encode should error
	_, err := Gob.Encode(nil)
	if err == nil {
		t.Error("expected error for nil encoding")
	}

	// Decode should error
	if _, err = Gob.Decode(nil, nil); err == nil {
		t.Error("expected error for nil receiver")
	}

	var test string

	if _, err = Gob.Decode(nil, test); err == nil {
		t.Errorf("expected error for decoding to non-pointer %v", err)
	}
}

var encodings = []Encoding{Gob, JSON}

func TestEncoding(t *testing.T) {
	testString := "this string will be encoded and decoded again"

	for _, k := range encodings {
		enc, err := k.Encode(testString)
		if err != nil {
			t.Fatal(err)
		}

		var decoded string
		dec, err := k.Decode(enc, &decoded)
		if err != nil {
			t.Fatal(err)
		}

		if dec == nil {
			t.Fatalf("unexpected nil pointer")
		}

		s := dec.(*string)

		if *s != testString {
			t.Errorf("failed in en/decoding original value. expected %q, got, %s", testString, *s)
		}
	}
}
