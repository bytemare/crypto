package ristretto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/hash"
)

const (
	dstMaxLength = 255

	goodScalar = "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d0a"
	basePoint  = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	testApp         = "testRistretto255"
	testVersion     = "0.0"
	testCiphersuite = "cipherSuite"
)

type testGroup struct {
	name            string
	hashID          hash.Identifier
	app             string
	version         string
	scalar, element string // hex encoding of a scalar and element
	scal, elem      bool   // says whether the scalar or element is supposed to be valid
}

var (
	hashAlgs = []hash.Identifier{hash.SHA256, hash.SHA512, hash.SHA3_256, hash.SHA3_512, hash.SHAKE128, hash.SHAKE256}
	h2cInput = "H2C Input"
)

type h2c struct {
	hash.Identifier
	hash  string
	h2cID string
}

var h2cR255 = []*h2c{
	{
		Identifier: hash.SHA256,
		hash:       "f890112b9ac4945a4db5e9dcaac23603e6201b58387017f0b858f7b76ea02e4e",
		h2cID:      "ristretto255_XMD:SHA256_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA512,
		hash:       "86e7ca3545247c5b66acbce63e858e4142bbafb3647fe625e5d5e8ee0e624624",
		h2cID:      "ristretto255_XMD:SHA512_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA3_256,
		hash:       "32c55e0b6167dc01288f84ab864103aef0fb05151409439db9e49bd760e50953",
		h2cID:      "ristretto255_XMD:SHA3-256_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA3_512,
		hash:       "6c98f379e15cfbd28641137d9cd44f21eed6e66a967d6e66a97863af624ad437",
		h2cID:      "ristretto255_XMD:SHA3-512_R255MAP_RO_",
	},
	{
		Identifier: hash.SHAKE128,
		hash:       "840a80e25d220ffec374a45f42ca2fa9fd882279dfd97e5cf9bef8f293469130",
		h2cID:      "ristretto255_XOF:SHAKE128_R255MAP_RO_",
	},
	{
		Identifier: hash.SHAKE256,
		hash:       "fa39869a29dbefebbca9e4635d8f41cc96a504a06174baf013a3c341d865481c",
		h2cID:      "ristretto255_XOF:SHAKE256_R255MAP_RO_",
	},
}

// todo: adapt to different hashing algorithms
var tests = []testGroup{
	{
		name:    "Valid element (base point), valid scalar",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: basePoint,
		scal:    true,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (size)",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (encoding)",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid scalar, bad element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    true,
		elem:    false,
	},
	{
		name:    "Nil scalar, bad element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    false,
		elem:    false,
	},
	{
		name:    "Nil scalar, nil element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "",
		scal:    false,
		elem:    false,
	},
}

func dst(app, version, h2c string, identifier byte) []byte {
	return []byte(fmt.Sprintf("%s-V%s-CS%v-%s", app, version, identifier, h2c))
}

func TestNewSucced(t *testing.T) {
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)

	for _, h := range hashAlgs {
		assert.NotPanics(t, func() {
			New(h, dst)
		}, "Should not panic with valid parameters")
	}
}

func TestNewFail(t *testing.T) {
	// New fails on h2c suite creation with nil dst
	assert.Panics(t, func() {
		New(tests[0].hashID, nil)
	}, "Should panic with nil DST")

	// New fails on h2c suite creation with empty dst
	assert.Panics(t, func() {
		New(tests[0].hashID, []byte(""))
	}, "Should panic with empty DST")
}

func TestNilScalar(t *testing.T) {
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)
	g := New(tests[0].hashID, dst)

	_, err := g.NewScalar().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestScalar(t *testing.T) {
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(tt.hashID, dst)

			s := g.NewScalar().Random()
			if len(s.Bytes()) != canonicalEncodingLength {
				t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
			}

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.scalar)
			if err != nil {
				t.Fatalf("#%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			s, err = g.NewScalar().Decode(encoding)

			switch tt.scal {
			case false:
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				if s != nil {
					t.Fatalf("unexpected nil scalar for %s", tt.name)
				}
			case true:
				if err != nil {
					t.Fatalf("%s : unexpected error, got %v", tt.name, err)
				}

				if s == nil {
					t.Fatal("scalar is nil, should not happen")
				}

				if len(s.Bytes()) != canonicalEncodingLength {
					t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
				}

				cpy, _ := g.NewScalar().Decode(s.Bytes())
				cpy = cpy.Invert()
				if bytes.Equal(cpy.Bytes(), s.Bytes()) {
					t.Fatal("scalar inversion resulted in same scalar")
				}

				//if string(s.Group()) != string(group.Ristretto255) {
				//	t.Fatalf("wrong group identifier. Expected %s, got %s", string(group.Ristretto255), s.Group())
				//}
			}
		})
	}
}

func TestNilElement(t *testing.T) {
	// Test if the element in the test is the base point
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)
	g := New(tests[0].hashID, dst)

	_, err := g.NewElement().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestElement(t *testing.T) {
	// Test if the element in the test is the base point
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)
	g := New(tests[0].hashID, dst)

	bp := g.NewElement().(*Element).Base()

	// Grab the bytes of the encoding
	encoding, err := hex.DecodeString(tests[0].element)
	if err != nil {
		t.Fatalf("%s: bad hex encoding in test vector: %v", tests[0].name, err)
	}

	if !bytes.Equal(bp.Bytes(), encoding) {
		t.Fatalf("%s: element doesn't decode to basepoint", tests[0].name)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(tt.hashID, dst)

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.element)
			if err != nil {
				t.Fatalf("%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			// Test decoding
			e, err := g.NewElement().Decode(encoding)

			switch tt.elem {
			case false:
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				if e != nil {
					t.Fatalf("%s : element is not nil but should have failed on decoding", tt.name)
				}

			case true:
				if err != nil {
					t.Fatalf("%s : unexpected error, got %v", tt.name, err)
				}

				if e == nil {
					t.Fatalf("%s : element is nil but should not have failed on decoding", tt.name)
				}

				// Test encoding
				if !bytes.Equal(encoding, e.Bytes()) {
					t.Fatalf("%s : Decoding and encoding doesn't return the same bytes", tt.name)
				}

				//if string(e.Group()) != string(group.Ristretto255) {
				//	t.Fatalf("wrong group identifier. Expected %s, got %s", string(group.Ristretto255), e.Group())
				//}
			}
		})
	}
}

func TestHashToCurveSucceed(t *testing.T) {
	for _, h := range h2cR255 {
		t.Run(string(h.Identifier), func(t *testing.T) {
			dst := dst(testApp, testVersion, testCiphersuite, 0x02)

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(h.hash)
			if err != nil {
				t.Fatalf("%v: bad hex encoding in test vector: %v", h.Identifier, err)
			}

			g := New(h.Identifier, dst)
			m := g.HashToGroup([]byte(h2cInput))

			if !bytes.Equal(encoding, m.Bytes()) {
				t.Fatalf("encodings do not match. expected %v, got %v", hex.EncodeToString(encoding), hex.EncodeToString(m.Bytes()))
			}

			// Try again with very long DST
			proto := strings.Repeat("a", dstMaxLength+1)
			assert.NotPanics(t, func() {
				_ = New(h.Identifier, []byte(proto))
			}, "expected no panic with very long dst")
		})
	}
}

func TestMultiplication(t *testing.T) {
	dst := dst(testApp, testVersion, testCiphersuite, 0x02)
	g := New(tests[0].hashID, dst)

	assert.Panics(t, func() {
		_ = g.NewElement().Mult(nil)
	}, "expected panic on multiplying with nil scalar")

	bp := g.NewElement().(*Element).Base()
	rs := g.NewScalar().Random()

	//
	m1 := bp.Mult(rs)

	//
	m2, err := g.MultBytes(rs.Bytes(), g.NewElement().(*Element).Base().Bytes())
	if err != nil {
		t.Fatalf("unexpected err ; %v", err)
	}

	if !bytes.Equal(m1.Bytes(), m2.Bytes()) {
		t.Fatalf("expected equality in multiplication")
	}

	// Blind and unblind
	bp = g.NewElement().(*Element).Base()
	blinded := bp.Mult(rs)

	if bytes.Equal(blinded.Bytes(), g.NewElement().(*Element).Base().Bytes()) {
		t.Fatalf("failed multiplication : didn't change")
	}

	if blinded.IsIdentity() {
		t.Fatalf("failed multiplication : is identity")
	}

	// unblind
	assert.Panics(t, func() {
		_ = bp.InvertMult(nil)
	}, "expect panic when invertmult with nil scalar")

	unblinded := blinded.InvertMult(rs)

	if !bytes.Equal(unblinded.Bytes(), g.Base().Bytes()) {
		t.Fatalf("failed multiplication : unblinding didn't revert")
	}

	// Multiply from byte values
	element := g.NewElement().(*Element).Base()
	scalar := g.NewScalar().Random()

	mult := g.NewElement().(*Element).Base().Mult(scalar)

	bm, err := g.MultBytes(scalar.Bytes(), element.Bytes())
	if err != nil {
		t.Fatalf("MultBytes errored for []bytes multiplication")
	}

	if !bytes.Equal(mult.Bytes(), bm.Bytes()) {
		t.Fatalf("MultBytes failed. expected %x, got %x", mult.Bytes(), bm.Bytes())
	}

	// Multiply with invalid values
	if _, err := g.MultBytes(nil, nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}

	if _, err := g.MultBytes(scalar.Bytes(), nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}
}

func TestScalarArithmetic(t *testing.T) {
	g := New(hash.SHA512, []byte("dst"))

	// Test Addition and Substraction
	s := g.NewScalar().Random()
	c := s.Copy()
	assert.Equal(t, s.Add(nil).Bytes(), s.Bytes())
	a := s.Add(s)
	assert.Equal(t, a.Sub(nil).Bytes(), a.Bytes())
	r := a.Sub(c)
	assert.Equal(t, r.Bytes(), c.Bytes())

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	c = s.Copy()
	cc := c.Copy()
	m := s.Mult(c)
	i := c.Invert().Mult(m)
	assert.Equal(t, i.Bytes(), cc.Bytes())
}

func TestPointArithmetic(t *testing.T) {
	g := New(hash.SHA512, []byte("dst"))
	input := []byte("input")

	// Test Addition and Subtraction
	p := g.Base()
	c := p.Copy()
	assert.Panics(t, func() { p.Add(nil) })
	a := p.Add(p)
	assert.Panics(t, func() { a.Sub(nil) })
	r := a.Sub(c)
	assert.Equal(t, r.Bytes(), c.Bytes())

	// Test Multiplication and inversion
	p = g.Base()
	s := g.HashToScalar(input)
	penc := p.Bytes()
	senc := s.Bytes()
	m := p.Mult(s)
	e, err := g.MultBytes(senc, penc)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, m.Bytes(), e.Bytes())
	assert.Panics(t, func() { m.InvertMult(nil) })
	i := m.InvertMult(s)
	assert.Equal(t, i.Bytes(), p.Bytes())

	// Test identity
	p = p.Sub(p)
	assert.True(t, p.IsIdentity())
	assert.Equal(t, p.Bytes(), g.Identity().Bytes())
}
