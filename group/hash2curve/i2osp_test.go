// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package hash2curve provides hash-to-curve compatible input expansion.
package hash2curve

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type i2ospTest struct {
	value   int
	size    int
	encoded []byte
}

var i2ospVectors = []i2ospTest{
	{
		0, 1, []byte{0},
	},
	{
		1, 1, []byte{1},
	},
	{
		255, 1, []byte{0xff},
	},
	{
		256, 2, []byte{0x01, 0x00},
	},
	{
		65535, 2, []byte{0xff, 0xff},
	},
}

func TestI2OSP(t *testing.T) {
	for i, v := range i2ospVectors {
		t.Run(fmt.Sprintf("%d - %d - %v", v.value, v.size, v.encoded), func(t *testing.T) {
			r := i2osp(v.value, v.size)

			if !bytes.Equal(r, v.encoded) {
				t.Fatalf("invalid encoding for %d. Expected '%s', got '%v'", i, hex.EncodeToString(v.encoded), hex.EncodeToString(r))
			}

			value := os2ip(v.encoded)
			if v.value != value {
				t.Fatalf("invalid decoding for %d. Expected %d, got %d", i, v.value, value)
			}
		})
	}

	length := -1
	assert.PanicsWithError(t, errLengthNegative.Error(), func() {
		_ = i2osp(1, length)
	}, "expected panic with negative length")

	length = 0
	assert.PanicsWithError(t, errLengthNegative.Error(), func() {
		_ = i2osp(1, length)
	}, "expected panic with 0 length")

	length = 5
	assert.PanicsWithError(t, errLengthTooBig.Error(), func() {
		_ = i2osp(1, length)
	}, "expected panic with length too high")

	negative := -1
	assert.PanicsWithError(t, errInputNegative.Error(), func() {
		_ = i2osp(negative, 4)
	}, "expected panic with negative input")

	tooLarge := 1 << 8
	length = 1
	assert.PanicsWithError(t, errInputLarge.Error(), func() {
		_ = i2osp(tooLarge, length)
	}, "expected panic with exceeding value for the length")

	lengths := map[int]int{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := i2osp(k, v)

		if len(r) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}
