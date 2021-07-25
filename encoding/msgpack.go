// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	"github.com/vmihailenco/msgpack/v5"
)

const sMsgPack = "MessagePack"

func msgPackDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	err := msgpack.Unmarshal(encoded, receiver)

	return receiver, err
}
