// SPDX-License-Group: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group

import "testing"

func TestAvailability(t *testing.T) {
	for id := range registered {
		if !id.Available() {
			t.Errorf("'%s' is not available, but should be", id.String())
		}
	}

	wrong := maxID
	if wrong.Available() {
		t.Errorf("%v is considered available when it must not", wrong)
	}
}
