package hash2curve

import (
	"testing"

	H2C "github.com/armfazh/h2c-go-ref"
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

func testPointArithmetic(t *testing.T, suite H2C.SuiteID, input, dst []byte) {
	g := New(suite, dst)

	// Test Addition and Subtraction
	base := g.Base()
	c := base.Copy()
	assert.Panics(t, func() { base.Add(nil) })
	a := base.Add(base)
	assert.Panics(t, func() { a.Sub(nil) })
	r := a.Sub(c)
	assert.Equal(t, r.Bytes(), c.Bytes())

	// Test Multiplication and inversion
	base = g.Base()
	s := g.HashToScalar(input)
	penc := base.Bytes()
	senc := s.Bytes()
	m := base.Mult(s)
	e, err := g.MultBytes(senc, penc)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, m.Bytes(), e.Bytes())
	assert.PanicsWithError(t, errParamNilScalar.Error(), func() { m.InvertMult(nil) })
	i := m.InvertMult(s)
	assert.Equal(t, i.Bytes(), base.Bytes())

	// Test identity
	id := base.Sub(base)
	assert.True(t, id.IsIdentity())
}

func TestPointArithmetic(t *testing.T) {
	dst := []byte("dst")
	input := []byte("input")

	for id := range curves {
		t.Run(string(id), func(t *testing.T) {
			testPointArithmetic(t, id, input, dst)
		})
	}
}
