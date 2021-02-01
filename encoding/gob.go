package encoding

import (
	"bytes"
	"encoding/gob"
)

const sGob  = "Gob"

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