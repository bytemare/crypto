package h2r

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bytemare/cryptotools/hash"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type vector struct {
	dstPrime     []byte
	lenInBytes   int
	msg          []byte
	msgPrime     []byte
	uniformBytes []byte
}

type vectorStrings struct {
	DSTPrime     string `json:"DST_prime"`
	LenInBytes   string `json:"len_in_bytes"`
	Msg          string `json:"msg"`
	MsgPrime     string `json:"msg_prime"`
	UniformBytes string `json:"uniform_bytes"`
}

func (vs *vectorStrings) decode() (*vector, error) {
	v := &vector{}
	var err error

	v.dstPrime, err = hex.DecodeString(vs.DSTPrime)
	if err != nil {
		return nil, err
	}

	length, err := strconv.ParseUint(vs.LenInBytes[2:], 16, 32)
	if err != nil {
		return nil, err
	}

	v.lenInBytes = int(length)
	v.msg = []byte(vs.Msg)

	v.msgPrime, err = hex.DecodeString(vs.MsgPrime)
	if err != nil {
		return nil, err
	}

	v.uniformBytes, err = hex.DecodeString(vs.UniformBytes)
	if err != nil {
		return nil, err
	}

	return v, err
}

type set struct {
	DST   string          `json:"DST"`
	Hash  string          `json:"hash"`
	Name  string          `json:"name"`
	Tests []vectorStrings `json:"tests"`
}

func mapHash(name string) hash.Identifier {
	switch name {
	case "SHA256":
		return hash.SHA256
	case "SHA512":
		return hash.SHA512
	case "SHAKE128":
		return hash.SHAKE128
	default:
		return 0
	}
}

func (s *set) run(t *testing.T) {
	dst := []byte(s.DST)
	h := New(dst, mapHash(s.Hash))

	for i, test := range s.Tests {
		t.Run(fmt.Sprintf("%s : Vector %d", s.Hash, i), func(t *testing.T) {
			v, err := test.decode()
			if err != nil {
				t.Fatalf("%d : %v", i, err)
			}

			dstPrime := h.dstPrime()
			if !bytes.Equal(v.dstPrime, dstPrime) {
				t.Fatalf("%d : invalid DST prime.", i)
			}

			msgPrime := h.msgPrime(v.msg, v.lenInBytes)
			if !bytes.Equal(v.msgPrime, msgPrime) {
				t.Fatalf("%d : invalid msg prime.", i)
			}

			x := h.Expand(v.msg, v.lenInBytes)
			//if !bytes.Equal(v.uniformBytes, x) {
			if !assert.Equal(t, v.uniformBytes, x) {
				t.Fatalf("%d : invalid hash (length %d vs %d).", i, len(x), v.lenInBytes)
			}
		})
	}
}

func TestExpander(t *testing.T) {
	if err := filepath.Walk("vectors",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, errOpen := os.Open(path)
			if errOpen != nil {
				return errOpen
			}

			defer file.Close()

			val, errRead := ioutil.ReadAll(file)
			if errRead != nil {
				return errRead
			}

			var s set
			errJSON := json.Unmarshal(val, &s)
			if errJSON != nil {
				return errJSON
			}

			s.run(t)

			return nil
		}); err != nil {
		t.Fatalf("error opening set vectorStrings: %v", err)
	}
}
