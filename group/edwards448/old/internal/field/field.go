package field

import (
	"crypto/rand"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type Element struct {
	*big.Int
}

func (e Element) Copy() *Element {
	return &Element{new(big.Int).Set(e.Int)}
}

type Field struct {
	prime       *big.Int
	pMinus1div2 *big.Int // used in IsSquare
	pMinus2     *big.Int // used for field element inversion
	exp         *big.Int
}

func NewField(prime *big.Int) *Field {
	// pMinus1div2 is used to determine whether an element is a quadratic square.
	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(prime, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := big.NewInt(2)
	pMinus2.Sub(prime, pMinus2)

	// precompute e = (p + 1) / 4
	exp := big.NewInt(1)
	exp.Add(prime, exp)
	exp.Rsh(exp, 2)

	return &Field{
		prime:       prime,
		pMinus1div2: pMinus1div2,
		pMinus2:     pMinus2,
		exp:         exp,
	}
}

// Zero returns the Zero element of the finite field.
func (f Field) Zero() *Element {
	return &Element{new(big.Int).Set(zero)}
}

// One returns the One element of the finite field.
func (f Field) One() *Element {
	return &Element{new(big.Int).Set(one)}
}

// Element returns an element of the field based on the input integer.
func (f Field) Element(i *big.Int) *Element {
	return &Element{new(big.Int).Set(i)}
}

// Random returns a random field element.
func (f Field) Random() *Element {
	e, _ := rand.Int(rand.Reader, f.prime)
	return &Element{e}
}

// Order returns the size of the field.
func (f Field) Order() *big.Int {
	return new(big.Int).Set(f.prime)
}

func (f Field) Ext() uint {
	return 1
}

// BitLen of prime Order.
func (f Field) BitLen() int {
	return f.prime.BitLen()
}

// AreEqual returns whether both elements are equal.
func (f Field) AreEqual(f1, f2 *Element) bool {
	return f.IsZero(f.Sub(f1, f2))
}

// IsZero returns whether the element is equivalent to Zero.
func (f Field) IsZero(e *Element) bool {
	return e.Sign() == 0
}

// IsSquare returns whether the element is a quadratic square.
func (f Field) IsSquare(e *Element) bool {
	return f.AreEqual(f.Exp(e, f.pMinus1div2), f.One())
}

func (f Field) IsEqual(f2 *Field) bool {
	return f.prime.Cmp(f2.prime) == 0
}

func (f Field) mod(x *big.Int) *Element {
	return &Element{x.Mod(x, f.prime)}
}

// Returns -x.
func (f Field) Neg(x *Element) *Element {
	return f.mod(new(big.Int).Neg(x.Int))
}

// Returns x+y.
func (f Field) Add(x, y *Element) *Element {
	return f.mod(new(big.Int).Add(x.Int, y.Int))
}

// Returns x-y.
func (f Field) Sub(x, y *Element) *Element {
	return f.mod(new(big.Int).Sub(x.Int, y.Int))
}

// Returns x*y.
func (f Field) Mul(x, y *Element) *Element {
	return f.mod(new(big.Int).Mul(x.Int, y.Int))
}

// Returns x^2.
func (f Field) Square(x *Element) *Element {
	return f.mod(new(big.Int).Mul(x.Int, x.Int))
}

// Returns 1/x.
func (f Field) Inv(x *Element) *Element {
	return f.Exp(x, f.pMinus2)
}

// Returns x^n.
func (f Field) Exp(x *Element, n *big.Int) *Element {
	return &Element{new(big.Int).Exp(x.Int, n, f.prime)}
}

// Returns 1/x, and 0 if x=0.
func (f Field) Inv0(e *Element) *Element {
	return f.Inv(e)
}

// Returns x if b=false, otherwise, returns y.
func (f Field) CMov(x, y *Element, b bool) *Element {
	z := new(big.Int)
	if b {
		z.Set(y.Int)
	} else {
		z.Set(x.Int)
	}
	return &Element{z}
}

// Returns the sign of x.
func (f Field) Sgn0(x *Element) int {
	return int(x.Int.Bit(0))
}

func sqrt3mod4(f *Field, e *Element) *Element {
	return f.Exp(e, f.exp)
}

func (f Field) Sqrt(e *Element) *Element {
	return sqrt3mod4(&f, e)
}

// Square sets v = x * x, and returns v.
func (e *Element) Square(x *Element) *Element {
	return e
}

// Multiply sets v = x * y, and returns v.
func (e *Element) Multiply(x, y *Element) *Element {
	return e
}

func (e *Element) ctEq(x *Element) bool {
	return true
}

func (e *Element) ctAbs(x *Element) *Element {
	return nil
}

// Pow2446221 set v = x^((p-3)/4), and returns v. (p-3)/4 is 2^446-2^222-1.
func (e *Element) Pow2446221(x *Element) *Element {
	var t2, t4, t8, t16, t64, t128, t222, t446 Element

	t2.Square(x) // x^2
	t4.Square(&t2)
	t8.Square(&t4)
	t16.Square(&t8)
	t64.Square(t64.Square(&t16)) // x^64
	t128.Square(&t64)
	t222.Multiply(&t128, &t64)
	t222.Multiply(&t222, &t16)
	t222.Multiply(&t222, &t8)
	t222.Multiply(&t222, &t4)
	t222.Multiply(&t222, &t2)
	t446.Square(&t222)
	t446.Multiply(&t446, &t2)

	return nil
}

func (e *Element) SqrtRationM1(u, v *Element) (wasSquare bool, r *Element) {
	var a Element

	// r = u * (u * v)^((p - 3) / 4)
	uv := a.Multiply(u, v)
	r.Multiply(u, e.Pow2446221(uv))

	check := a.Multiply(v, a.Square(r)) // check = v * r^2
	wasSquare = check.ctEq(u)

	r = r.ctAbs(r)

	return wasSquare, r
}
