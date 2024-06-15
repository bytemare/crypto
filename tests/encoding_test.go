package group_test

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"strings"
	"testing"
)

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	MarshalJSON() ([]byte, error)
	UnmarshalJSON(data []byte) error
	Hex() string
	DecodeHex(h string) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()
	hexed := thing1.Hex()

	jsoned, err := thing1.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output."+
			"\twant: %v\tgot : %v", encoded, marshalled)
	}

	if hex.EncodeToString(encoded) != hexed {
		t.Fatalf("Failed hex encoding, want %q, got %q", hex.EncodeToString(encoded), hexed)
	}

	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v. Value: %v", err, hex.EncodeToString(encoded))
	}

	if err := thing2.UnmarshalJSON(jsoned); err != nil {
		t.Fatalf("UnmarshalJSON() failed on a valid encoding: %v", err)
	}

	if err := thing2.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() failed on a valid encoding: %v", err)
	}

	if err := thing2.DecodeHex(hexed); err != nil {
		t.Fatalf("DecodeHex() failed on valid hex encoding: %v", err)
	}
}

func TestEncoding(t *testing.T) {
	testAll(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testEncoding(t, scalar, g.NewScalar())

		scalar = g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testEncoding(t, element, g.NewElement())
	})
}

func testDecodingHexFails(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	// malformed string
	hexed := thing1.Hex()
	malformed := []rune(hexed)
	malformed[0] = []rune("_")[0]

	if err := thing2.DecodeHex(string(malformed)); err == nil {
		t.Fatal("expected error on malformed string")
	} else if !strings.HasSuffix(err.Error(), "DecodeHex: encoding/hex: invalid byte: U+005F '_'") {
		t.Fatalf("unexpected error: %q", err)
	}
}

func TestEncoding_Hex_Fails(t *testing.T) {
	testAll(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testEncoding(t, scalar, g.NewScalar())

		scalar = g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testEncoding(t, element, g.NewElement())

		// Hex fails
		testDecodingHexFails(t, scalar, g.NewScalar())
		testDecodingHexFails(t, element, g.NewElement())

		// Doesn't yield the same decoded result
		scalar = g.NewScalar().Random()
		s := g.NewScalar()
		if err := s.DecodeHex(scalar.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if s.Equal(scalar) != 1 {
			t.Fatal(errExpectedEquality)
		}

		element = g.Base().Multiply(scalar)
		e := g.NewElement()
		if err := e.DecodeHex(element.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if e.Equal(element) != 1 {
			t.Fatal(errExpectedEquality)
		}
	})
}
