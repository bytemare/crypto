package encoding

import "encoding/json"

const sJSON = "JSON"

func jsonDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	err := json.Unmarshal(encoded, receiver)

	return receiver, err
}