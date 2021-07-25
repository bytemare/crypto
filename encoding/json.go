// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import "encoding/json"

const sJSON = "JSON"

func jsonDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	err := json.Unmarshal(encoded, receiver)

	return receiver, err
}
