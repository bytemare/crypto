// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package mhf

import (
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPBKDF2iterations = 10000
	pbkdf2s                 = "PBKDF2"
	pbkdf2Format            = "%s(%d-SHA512)"
)

var defaultPBKDF2Hash = sha512.New

type pbkdf2mhf struct {
	iterations int
}

func pbkdf2New() memoryHardFunction {
	return &pbkdf2mhf{
		iterations: defaultPBKDF2iterations,
	}
}

func (p *pbkdf2mhf) Harden(password, salt []byte, length int) []byte {
	return pbkdf2.Key(password, salt, p.iterations, length, defaultPBKDF2Hash)
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (p *pbkdf2mhf) Parameterize(parameters ...int) {
	if len(parameters) != 1 {
		panic(errParams)
	}

	p.iterations = parameters[0]
}

func (p *pbkdf2mhf) String() string {
	return fmt.Sprintf(pbkdf2Format, pbkdf2s, p.iterations)
}

func (p *pbkdf2mhf) params() []int {
	return []int{p.iterations}
}
