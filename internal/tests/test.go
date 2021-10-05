// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package crypto_tests

import "fmt"

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return
}

func ExpectPanic(expectedError error, f func()) (bool, string) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, "no panic"
	}

	if expectedError == nil {
		return true, ""
	}

	if err == nil {
		return false, "panic but no message"
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Sprintf("expected %q, got %q", expectedError, err)
	}

	return true, ""
}
