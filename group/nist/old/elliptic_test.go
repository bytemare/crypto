package internal

import (
	"crypto/elliptic"
	"encoding/hex"
	"log"
	"math/big"
	"testing"
)

type test struct {
	name  string
	group func() *Group
}

func testGroups() []*test {
	return []*test{
		{"P256", P256},
		{"P384", P384},
		{"P521", P521},
	}
}

func testAll(t *testing.T, f func(*testing.T, *test)) {
	for _, test := range testGroups() {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
		})
	}
}

func TestInfinity(t *testing.T) {
	testAll(t, func(t *testing.T, tt *test) {
		testInfinity(t, tt.group())
	})
}

func testInfinity(t *testing.T, group *Group) {
	private := group.NewScalar().Random()
	public := group.NewPoint().Mult(private, group.Base())

	// Set faulty scalar.
	nScalar := &Scalar{
		s: new(big.Int).Set(group.scalarField.prime),
		f: group.scalarField,
	}

	// Verify multiplication.
	p := public.Mult(nScalar, public)
	if p.x.Sign() != 0 || p.x.Sign() != 0 {
		t.Errorf("x^q != ∞")
	}

	// Assert point at infinity.
	if !p.IsIdentity() {
		t.Error("IsIdentity(∞) == false")
	}

	// Set 0 scalar.
	nScalar.s.SetInt64(0)

	// Verify multiplication.
	p = public.Mult(nScalar, public)
	if p.x.Sign() != 0 || p.x.Sign() != 0 {
		t.Errorf("b^0 != ∞")
		p.x.SetInt64(0)
		p.y.SetInt64(0)
	}

	// Assert point at infinity.
	if !p.IsIdentity() {
		t.Error("IsIdentity(∞) == false")
	}

	p2 := group.NewPoint().double(p)
	if p2.x.Sign() != 0 || p2.y.Sign() != 0 {
		t.Errorf("2∞ != ∞")
	}

	// Assert point at infinity.
	if !p.IsIdentity() {
		t.Error("IsIdentity(∞) == false")
	}

	baseX := group.gx
	baseY := group.gy

	p3 := group.NewPoint().Add(group.Base(), p)
	if p3.x.Cmp(baseX) != 0 || p3.y.Cmp(baseY) != 0 {
		t.Errorf("x+∞ != x")
	}

	// Assert point at infinity.
	if !p.IsIdentity() {
		t.Error("IsIdentity(∞) == false")
	}

	p4 := group.NewPoint().Add(p, group.Base())
	if p4.x.Cmp(baseX) != 0 || p4.y.Cmp(baseY) != 0 {
		t.Errorf("∞+x != x")
	}

	// Assert point at infinity.
	if !p.IsIdentity() {
		t.Error("IsIdentity(∞) == false")
	}

	if group.curve.isOnCurve(p) {
		t.Errorf("IsOnCurve(∞) == true")
	}

	t.Log(hex.EncodeToString(p.Bytes()))

	if _, err := group.NewPoint().Decode(p.Bytes()); err == nil {
		t.Error("Decoding(Encode(∞)) did not return an error")
	}

	if _, err := group.NewPoint().Decode([]byte{0x00}); err == nil {
		t.Errorf("Unmarshal(∞) did not return an error")
	}
}

func TestOffP521(t *testing.T) {
	c := elliptic.P521()
	log.Println(c.IsOnCurve(new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)))
	log.Println(c.IsOnCurve(big.NewInt(1), big.NewInt(1)))
	log.Println(elliptic.MarshalCompressed(c, big.NewInt(1), big.NewInt(1)))
	p := P521().NewPoint()
	p.x = big.NewInt(1)
	p.y = big.NewInt(1)
	log.Println(p.Bytes())
	log.Println(elliptic.Unmarshal(c, elliptic.Marshal(c, big.NewInt(1), big.NewInt(1))))
	log.Println(P521().NewPoint().Decode(p.Bytes()))
}

func TestOffCurve(t *testing.T) {
	testAll(t, func(t *testing.T, tt *test) {
		group := tt.group()
		p := group.NewPoint()
		p.x = big.NewInt(1)
		p.y = big.NewInt(1)
		if group.curve.isOnCurve(p) {
			t.Errorf("point off curve is claimed to be on the curve")
		}
		//b := p.Bytes()
		//_, err := group.NewPoint().Decode(b)
		//if err == nil {
		//	t.Errorf("unmarshaling a point not on the curve succeeded")
		//}
	})
}
