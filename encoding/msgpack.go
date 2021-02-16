package encoding

import (
	"github.com/vmihailenco/msgpack/v5"
)

const sMsgPack = "MessagePack"

func msgPackDecode(encoded []byte, receiver interface{}) (interface{}, error) {
	err := msgpack.Unmarshal(encoded, receiver)

	return receiver, err
}
