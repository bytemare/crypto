package nist

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash2curve"
)

func s2int(s string) *big.Int {
	if p, _ := new(big.Int).SetString(s, 0); p != nil {
		return p
	}

	panic("invalid string to convert")
}

type mapping struct {
	hash      crypto.Hash
	secLength int
	z         *big.Int
	c1, c2    *big.Int
}

type curve[point nistECPoint[point]] struct {
	field    *field
	a, b     *big.Int
	NewPoint func() point
	mapping
}

func (c *curve[point]) setMapping(hash crypto.Hash, z string, secLength int) {
	c.mapping.hash = hash
	c.mapping.secLength = secLength
	c.mapping.z = s2int(z)
	c.preComputeMap()
}

func (c *curve[point]) preComputeMap() {
	t0 := c.field.Inv(c.a)         // 1/A
	t0 = c.field.Mul(t0, c.b)      // B/A
	c.mapping.c1 = c.field.neg(t0) // -B/A
	t0 = c.field.Inv(c.mapping.z)  // 1/Z
	c.mapping.c2 = c.field.neg(t0) // -1/
}

func (c *curve[point]) setCurveParams(prime *big.Int, b string, newPoint func() point) {
	c.field = NewField(prime)
	c.a = s2int("-3")
	c.b = s2int(b)
	c.NewPoint = newPoint
}

func (c *curve[point]) encodeXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 1, 1, c.secLength, c.field.prime)
	q := c.Map(u[0])
	// We can save cofactor clearing because it is 1.
	return q
}

func (c *curve[point]) hashXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 2, 1, c.secLength, c.field.prime)
	q0 := c.Map(u[0])
	q1 := c.Map(u[1])
	// We can save cofactor clearing because it is 1.
	return q0.Add(q0, q1)
}

func (c *curve[point]) sqrtRatio(e, v *big.Int) (bool, *big.Int) {
	F := c.field
	r := F.Inv(v)

	r = F.Mul(r, e)
	if F.IsSquare(r) {
		return true, F.Sqrt(r)
	}

	r = F.Mul(r, c.z)

	return false, F.Sqrt(r)
}

// Map implements the Simplified SWU method.
func (c *curve[point]) Map(e *big.Int) point {
	f := c.field
	var tv1, tv2, tv3, tv4, tv5, tv6, x, y *big.Int

	tv1 = f.Square(e)                             //    1.  tv1 = u^2
	tv1 = f.Mul(c.z, tv1)                         //    2.  tv1 = Z * tv1
	tv2 = f.Square(tv1)                           //    3.  tv2 = tv1^2
	tv2 = f.Add(tv2, tv1)                         //    4.  tv2 = tv2 + tv1
	tv3 = f.Add(tv2, f.One())                     //    5.  tv3 = tv2 + 1
	tv3 = f.Mul(c.b, tv3)                         //    6.  tv3 = B * tv3
	tv4 = f.CMov(c.z, f.neg(tv2), !f.IsZero(tv2)) //    7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	tv4 = f.Mul(c.a, tv4)                         //    8.  tv4 = A * tv4
	tv2 = f.Square(tv3)                           //    9.  tv2 = tv3^2
	tv6 = f.Square(tv4)                           //    10. tv6 = tv4^2
	tv5 = f.Mul(c.a, tv6)                         //    11. tv5 = A * tv6
	tv2 = f.Add(tv2, tv5)                         //    12. tv2 = tv2 + tv5
	tv2 = f.Mul(tv2, tv3)                         //    13. tv2 = tv2 * tv3
	tv6 = f.Mul(tv6, tv4)                         //    14. tv6 = tv6 * tv4
	tv5 = f.Mul(c.b, tv6)                         //    15. tv5 = B * tv6
	tv2 = f.Add(tv2, tv5)                         //    16. tv2 = tv2 + tv5
	x = f.Mul(tv1, tv3)                           //    17.   x = tv1 * tv3
	isGx1Square, y1 := c.sqrtRatio(tv2, tv6)      //    18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)
	y = f.Mul(tv1, e)                             //    19.   y = tv1 * u
	y = f.Mul(y, y1)                              //    20.   y = y * y1
	x = f.CMov(x, tv3, isGx1Square)               //    21.   x = CMOV(x, tv3, is_gx1_square)
	y = f.CMov(y, y1, isGx1Square)                //    22.   y = CMOV(y, y1, is_gx1_square)
	e1 := f.Sgn0(e) == f.Sgn0(y)                  //    23.  e1 = sgn0(u) == sgn0(y)
	y = f.CMov(f.neg(y), y, e1)                   //    24.   y = CMOV(-y, y, e1)
	tv4 = f.Inv(tv4)                              //    25.   x = x / tv4
	x = f.Mul(x, tv4)

	return c.affineToPoint(x, y)
}

var (
	decompressed256 = [65]byte{0x04}
	decompressed384 = [97]byte{0x04}
	decompressed521 = [133]byte{0x04}
)

func (c *curve[point]) affineToPoint(x, y *big.Int) point {
	var decompressed []byte

	byteLen := (c.field.BitLen() + 7) / 8
	switch byteLen {
	case 32:
		decompressed = decompressed256[:]
	case 48:
		decompressed = decompressed384[:]
	case 66:
		decompressed = decompressed521[:]
	}

	decompressed[0] = 0x04
	x.FillBytes(decompressed[1 : 1+byteLen])
	y.FillBytes(decompressed[1+byteLen:])

	p, err := c.NewPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
