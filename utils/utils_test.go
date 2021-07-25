// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package utils

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	length := 32
	r := RandomBytes(length)

	if len(r) != length {
		t.Errorf("invalid random output length. Expected %d, got %d", length, len(r))
	}
}

func TestConcatenate(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	expected := []byte("ab")

	c := Concatenate(0, a, b)

	if !bytes.Equal(c, expected) {
		t.Errorf("failed to concatenate. Expected %v, got %v", expected, c)
	}

	if Concatenate(0, nil) != nil {
		t.Error("expected nil output for nil input")
	}
}
