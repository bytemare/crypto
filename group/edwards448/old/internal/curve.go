package internal

import (
	"crypto"
	"github.com/bytemare/crypto/group/edwards448/internal/field"
	"math/big"
)

const (
	// all the following values must be moduled
	a = 1

	// = 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358
	d = -39081

	//
	z = -1

	oneMinusD  = 39082
	oneMinus2D = 78163

	sqrtMinusD    = 98944233647732219769177004876929019128417576295529901074099889598043702116001257856802131563896515373927712232092845883226922417596214
	invSqrtMinusD = 315019913931389607337177038330951043522456072897266928557328499619017160722351061360252776265186336876723201881398623946864393857820716
)

type Curve struct {
	field   *field.Field
	a, b, d *field.Element
	mapping
}

func setCurveParams(c *Curve, prime, a, d string) {
	c.field = field.NewField(s2int(prime))
	c.a = &field.Element{Int: s2int(a)}
	c.d = &field.Element{Int: s2int(d)}
}

type mapping struct {
	hash      crypto.Hash
	secLength int
	z         *field.Element
	c1, c2    *field.Element
}

func s2int(s string) *big.Int {
	if p, _ := new(big.Int).SetString(s, 0); p != nil {
		return p
	}

	panic("invalid string to convert")
}

func setMapping(c *Curve, hash crypto.Hash, z string, secLength int) {
	c.mapping.hash = hash
	c.mapping.secLength = secLength
	c.mapping.z = &field.Element{Int: s2int(z)}
	preComputeMap(c)
}

func preComputeMap(c *Curve) {
	t0 := c.field.Inv(c.a)         // 1/A
	t0 = c.field.Mul(t0, c.b)      // B/A
	c.mapping.c1 = c.field.Neg(t0) // -B/A
	t0 = c.field.Inv(c.mapping.z)  // 1/Z
	c.mapping.c2 = c.field.Neg(t0) // -1/
}

func (c Curve) Point(x, y *field.Element) *Point {
	return &Point{
		curve: &c,
		x:     x,
		y:     y,
	}
}

func (c Curve) add(u, v Point) *Point {
	f := c.field

	var t0, t1, t2, t3 *field.Element
	t0 = f.Mul(c.d, u.x)    // Dx1
	t0 = f.Mul(t0, u.y)     // Dx1y1
	t0 = f.Mul(t0, v.x)     // Dx1y1x2
	t0 = f.Mul(t0, v.y)     // Dx1y1x2y2
	t2 = f.Add(f.One(), t0) // 1+Dx1y1x2y2
	t3 = f.Sub(f.One(), t0) // 1-Dx1y1x2y2
	t2 = f.Inv(t2)          // 1/(1+Dx1y1x2y2)
	t3 = f.Inv(t3)          // 1/(1-Dx1y1x2y2)

	t0 = f.Mul(u.x, v.y) // x1y2
	t1 = f.Mul(v.x, u.y) // x2y1
	t0 = f.Add(t0, t1)   // x1y2+x2y1
	x := f.Mul(t0, t2)   // (x1y2+x2y1)/(1+Dx1y1x2y2)

	t0 = f.Mul(u.y, v.y) // y1y2
	t1 = f.Mul(u.x, v.x) // x1x2
	t1 = f.Mul(t1, c.a)  // Ax1x2
	t0 = f.Sub(t0, t1)   // y1y2-Ax1x2
	y := f.Mul(t0, t3)   // (y1y2-Ax1x2)/(1-Dx1y1x2y2)

	return c.Point(x, y)
}

func (c Curve) Map(e *field.Element) *Point {
	f := c.field
	var t1 *field.Element
	var x1, x2, gx1, gx2, y2, x, y *field.Element
	var e1, e2, e3 bool
	t1 = f.Square(e)                               // 1.   t1 = u^2
	t1 = f.Mul(c.z, t1)                            // 2.   t1 = Z * t1              // Z * u^2
	e1 = f.AreEqual(t1, f.Element(big.NewInt(-1))) // 3.   e1 = t1 == -1            // exceptional case: Z * u^2 == -1
	t1 = f.CMov(t1, f.Zero(), e1)                  // 4.   t1 = CMOV(t1, 0, e1)     // if t1 == -1, set t1 = 0
	x1 = f.Add(t1, f.One())                        // 5.   x1 = t1 + 1
	x1 = f.Inv0(x1)                                // 6.   x1 = inv0(x1)
	x1 = f.Mul(f.Neg(c.a), x1)                     // 7.   x1 = -A * x1             // x1 = -A / (1 + Z * u^2)
	gx1 = f.Add(x1, c.a)                           // 8.  gx1 = x1 + A
	gx1 = f.Mul(gx1, x1)                           // 9.  gx1 = gx1 * x1
	gx1 = f.Add(gx1, c.b)                          // 10. gx1 = gx1 + B
	gx1 = f.Mul(gx1, x1)                           // 11. gx1 = gx1 * x1            // gx1 = x1^3 + A * x1^2 + B * x1
	x2 = f.Sub(f.Neg(x1), c.a)                     // 12.  x2 = -x1 - A
	gx2 = f.Mul(t1, gx1)                           // 13. gx2 = t1 * gx1
	e2 = f.IsSquare(gx1)                           // 14.  e2 = is_square(gx1)
	x = f.CMov(x2, x1, e2)                         // 15.   x = CMOV(x2, x1, e2)    // If is_square(gx1), x = x1, else x = x2
	y2 = f.CMov(gx2, gx1, e2)                      // 16.  y2 = CMOV(gx2, gx1, e2)  // If is_square(gx1), y2 = gx1, else y2 = gx2
	y = f.Sqrt(y2)                                 // 17.   y = sqrt(y2)
	e3 = f.Sgn0(y) == 1                            // 18.  e3 = sgn0(y) == 1
	eq := (e2 && !e3) || (!e2 && e3)               // 19.   e = e2 xor e3
	y = f.CMov(y, f.Neg(y), eq)                    //       y = CMOV(-y, y, e2 xor e3)

	return c.Point(x, y)
}
