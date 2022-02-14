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

	"golang.org/x/crypto/scrypt"
)

const (
	scrypts      = "Scrypt"
	scryptFormat = "%s(%d-%d-%d)"
)

var (
	defaultScryptn = 32768
	defaultScryptr = 8
	defaultScryptp = 1
)

type scryptKSF struct {
	n, r, p int
}

func scryptKSFNew() keyStretchingFunction {
	return &scryptKSF{
		n: defaultScryptn,
		r: defaultScryptr,
		p: defaultScryptp,
	}
}

func (s *scryptKSF) Harden(password, salt []byte, length int) []byte {
	k, err := scrypt.Key(password, salt, s.n, s.r, s.p, length)
	if err != nil {
		panic(fmt.Errorf("unexpected error : %w", err))
	}

	return k
}

// Parameterize replaces the functions parameters with the new ones. Must match the amount of parameters.
func (s *scryptKSF) Parameterize(parameters ...int) {
	if len(parameters) != 3 {
		panic(errParams)
	}

	s.n = parameters[0]
	s.r = parameters[1]
	s.p = parameters[2]
}

func (s *scryptKSF) String() string {
	return fmt.Sprintf(scryptFormat, scrypts, s.n, s.r, s.p)
}

func (s *scryptKSF) params() []int {
	return []int{s.n, s.r, s.p}
}
