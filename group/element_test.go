package group

import (
	"bytes"
	"github.com/bytemare/crypto/group/internal"
	"testing"

	errPanic "github.com/bytemare/crypto/internal"
)

func TestPoint_Decode(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		element := group.id.Base().Mult(group.id.NewScalar().Random())
		encoded := element.Bytes()
		decoded, err := group.id.NewElement().Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}

		if !element.Sub(decoded).IsIdentity() {
			t.Fatal("expected equality when en/decoding element")
		}
	})
}

func TestPoint_Arithmetic(t *testing.T) {
	testAll(t, func(t2 *testing.T, group *group) {
		testPointArithmetic(t, group.id)
	})
}

func testPointArithmetic(t *testing.T, g Group) {
	// Test Addition and Subtraction
	base := g.Base()

	// Expect panic when adding a nil Element.
	if hasPanic, _ := errPanic.ExpectPanic(nil, func() {
		base.Add(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}

	// Expect panic when subtracting a nil Element.
	if hasPanic, _ := errPanic.ExpectPanic(nil, func() {
		base.Sub(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}

	// Test base = base + base - base
	twoBase := base.Add(base)
	sub := twoBase.Sub(base)
	if !bytes.Equal(sub.Bytes(), base.Bytes()) {
		t.Fatal("expected equality")
	}

	// Test Scalar multiplication from structs and bytes
	base = g.Base()
	baseEnc := base.Bytes()
	s := g.NewScalar().Random()
	sEnc := s.Bytes()

	m := base.Mult(s)
	if m.IsIdentity() {
		t.Fatal("base mult s is identity")
	}

	e, err := g.MultBytes(sEnc, baseEnc)
	if err != nil {
		t.Fatal(err)
	}
	if e.IsIdentity() {
		t.Fatal("base MultBytes s is identity")
	}

	if !bytes.Equal(m.Bytes(), e.Bytes()) {
		t.Fatalf("expected equality for scalar mult of same base point\n\t%v\n\t%v", m.Bytes(), e.Bytes())
	}

	// Test multiplying with an inverted nil scalar
	if hasPanic, err := errPanic.ExpectPanic(internal.ErrParamNilScalar, func() {
		m.InvertMult(nil)
	}); !hasPanic {
		t.Fatalf("expected panic: %v", err)
	}
	i := m.InvertMult(s)
	if !bytes.Equal(i.Bytes(), base.Bytes()) {
		t.Fatal("not equal")
	}

	// Test identity
	id := base.Sub(base)
	if !id.IsIdentity() {
		t.Fatal("expected identity element")
	}
	if !bytes.Equal(id.Bytes(), g.NewElement().Bytes()) {
		t.Fatal("expected identity element for new element")
	}
}
