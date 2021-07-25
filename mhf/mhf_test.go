// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package mhf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/utils"
)

var (
	mhfs    = []Identifier{Argon2id, Scrypt, PBKDF2Sha512, Bcrypt}
	strings = []string{"Argon2id(1-65536-4)", "Scrypt(32768-8-1)", "PBKDF2(10000-SHA512)", "Bcrypt(10)"}
)

func TestAvailability(t *testing.T) {
	for _, i := range mhfs {
		if !i.Available() {
			t.Errorf("%s is not available, but should be", i)
		}
	}

	wrong := 0
	if Identifier(wrong).Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestMHF(t *testing.T) {
	password := []byte("password")
	salt := utils.RandomBytes(32)
	length := 32

	for _, m := range mhfs {
		t.Run(m.String(), func(t *testing.T) {
			assert.True(t, m.Available())

			assert.Equal(t, m.String(), strings[m-1])

			assert.NotPanics(t, func() {
				_ = m.Harden(password, salt, length)
			})

			h := m.Get()
			p := h.params()
			h.Parameterize(p...)
			assert.NotPanics(t, func() {
				_ = h.Harden(password, salt, length)
			})
		})
	}
}
