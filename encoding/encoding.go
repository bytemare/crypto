// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package encoding provides encoding and decoding capabilities for different encodings.
package encoding

import (
	"encoding/json"
	"errors"

	"github.com/vmihailenco/msgpack/v5"
)

// Encoding identifies referenced encoding formats.
type Encoding byte

const (

	// JSON encoding.
	JSON Encoding = 1 + iota

	// Gob encoding.
	Gob

	// MessagePack encoding.
	MessagePack

	maxID

	// Default is the default encoding used when none specified.
	Default = JSON
)

type (
	encoder func(v interface{}) ([]byte, error)
	decoder func(encoded []byte, receiver interface{}) (interface{}, error)
)

var (
	encoders map[Encoding]encoder
	decoders map[Encoding]decoder

	errInvalidID    = errors.New("invalid encoding identifier")
	errNotAvailable = errors.New("encoding is not available")
)

func (e Encoding) register(enc encoder, dec decoder) {
	encoders[e] = enc
	decoders[e] = dec
}

// Available returns nil if the encoding is available, and an error if not.
func (e Encoding) Available() error {
	if e == 0 || e >= maxID {
		return errInvalidID
	}

	if _, ok := encoders[e]; !ok {
		return errNotAvailable
	}

	return nil
}

// Encode returns the encoding of v in the receivers format.
func (e Encoding) Encode(v interface{}) ([]byte, error) {
	return encoders[e](v)
}

// Decode returns the receiver struct filled with the decoding of the encoded input. Returns an error if it fails.
func (e Encoding) Decode(encoded []byte, receiver interface{}) (interface{}, error) {
	return decoders[e](encoded, receiver)
}

// String implements the Stringer() interface.
func (e Encoding) String() string {
	switch e {
	case JSON:
		return sJSON
	case Gob:
		return sGob
	case MessagePack:
		return sMsgPack
	default:
		return ""
	}
}

func init() {
	encoders = make(map[Encoding]encoder)
	decoders = make(map[Encoding]decoder)

	JSON.register(json.Marshal, jsonDecode)
	Gob.register(gobEncode, gobDecode)
	MessagePack.register(msgpack.Marshal, msgPackDecode)
}
