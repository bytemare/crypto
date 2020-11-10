package hash2curve

import (
	"testing"

	"github.com/armfazh/h2c-go-ref"
	"github.com/stretchr/testify/assert"
)

func TestPointEncoding(t *testing.T) {
	dst := "Test-V00-CS123"
	input := "input datafqverqvbdbq"

	for id := range curves {
		t.Run(string(id), func(t *testing.T) {
			h := New(id, []byte(dst))
			e := h.HashToGroup([]byte(input))
			b := e.Bytes()
			n, err := h.NewElement().Decode(b)
			if err != nil {
				t.Fatal(err)
			}

			ne := e.(*Point)
			nn := n.(*Point)

			assert.True(t, ne.point.IsEqual(nn.point))
		})
	}
}

func TestPointArithmetic(t *testing.T) {
	g := New(h2c.Edwards25519_XMDSHA512_ELL2_RO_, []byte("dst"))
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
