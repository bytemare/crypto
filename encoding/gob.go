// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	"bytes"
	"encoding/gob"
)

const sGob = "Gob"

func gobEncode(v interface{}) ([]byte, error) {
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func gobDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	buffer := bytes.NewBuffer(encoded)

	dec := gob.NewDecoder(buffer)
	if err := dec.Decode(receiver); err != nil {
		return nil, err
	}

	return receiver, nil
}
