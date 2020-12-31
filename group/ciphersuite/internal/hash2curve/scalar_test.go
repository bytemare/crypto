package hash2curve

import (
	"testing"

	"github.com/armfazh/h2c-go-ref"
	"github.com/stretchr/testify/assert"
)

func TestScalarEncoding(t *testing.T) {
	h2p, err := h2c.Edwards25519_XMDSHA512_ELL2_RO_.Get([]byte("dst"))
	if err != nil {
		t.Fatal(err)
	}

	f := h2p.GetHashToScalar().GetScalarField()

	s := scalar(f).Random()

	enc := s.Bytes()
	s2, _ := scalar(f).Decode(enc)

	s3 := s2.(*Scalar)

	assert.True(t, s3.Equal(s.(*Scalar)))
}

func TestScalarArithmetic(t *testing.T) {
	g := New(h2c.Edwards25519_XMDSHA512_ELL2_RO_, []byte("dst"))

	// Test Addition and Substraction
	s := g.NewScalar().Random()
	assert.Equal(t, s.Add(nil).Bytes(), s.Bytes())
	a := s.Add(s)
	assert.Equal(t, a.Sub(nil).Bytes(), a.Bytes())
	r := a.Sub(s)
	assert.Equal(t, r.Bytes(), s.Bytes())

	// Test Multiplication and inversion
	s = g.NewScalar().Random()
	m := s.Mult(s)
	i := s.Invert().Mult(m)
	// i := m.Mult(s.Invert())
	assert.Equal(t, i.Bytes(), s.Bytes())
}
