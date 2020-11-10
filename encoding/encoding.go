// Package encoding provides encoding and decoding capabilities for different encodings.
package encoding

import (
	"bytes"
	"encoding/gob"
	"encoding/json"

	"github.com/bytemare/cryptotools/internal"
)

// Encoding identifies referenced encoding formats.
type Encoding byte

const (

	// JSON encoding.
	JSON Encoding = 1 + iota

	// Gob encoding.
	Gob

	maxID

	// todo : add hex and protobuf.

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

	errInvalidID    = internal.ParameterError("invalid encoding identifier")
	errNotAvailable = internal.ParameterError("encoding is not available")
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

func init() {
	encoders = make(map[Encoding]encoder)
	decoders = make(map[Encoding]decoder)

	JSON.register(json.Marshal, jsonDecode)
	Gob.register(gobEncode, gobDecode)
}

func jsonDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	err := json.Unmarshal(encoded, receiver)

	return receiver, err
}

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
