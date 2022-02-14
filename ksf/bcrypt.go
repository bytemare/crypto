// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ksf

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptFormat      = "%s(%d)"
	bcrypts           = "Bcrypt"
	defaultBcryptCost = 10
)

type bcryptKSF struct {
	time int
}

func bcryptNew() keyStretchingFunction {
	return &bcryptKSF{
		time: defaultBcryptCost,
	}
}

func (b *bcryptKSF) Harden(password, _ []byte, _ int) []byte {
	h, err := bcrypt.GenerateFromPassword(password, b.time)
	if err != nil {
		panic(err)
	}

	return h
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (b *bcryptKSF) Parameterize(parameters ...int) {
	if len(parameters) != 1 {
		panic(errParams)
	}

	b.time = parameters[0]
}

func (b *bcryptKSF) String() string {
	return fmt.Sprintf(bcryptFormat, bcrypts, b.time)
}

func (b *bcryptKSF) params() []int {
	return []int{b.time}
}
