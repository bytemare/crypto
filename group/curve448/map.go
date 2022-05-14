package curve448

import (
	fp448 "github.com/bytemare/crypto/group/twistedEdwards448/field"
)

/*
	Hashing to Edwards448 is better done with first hashing to curve448 and then mapping.
*/
func HashToCurve448(input, dst []byte) []byte {
	return nil
}

func Elligator2(u *fp448.Elt) (xn, xd, yn, yd *fp448.Elt) {

	prime := &fp448.Elt{}

	tv1 := &fp448.Elt{}

	tv1.Square(u)          // tv1 = u^2
	tv1.Mul(tv1, 2, prime) // tv1 = 2 * tv1
	xd.Add(xd)             //  xd = tv1 + 1         # Nonzero: -1 is square (mod p), tv1 is not
	// x1n = -J              # x1 = x1n / xd = -J / (1 + 2 * u^2)
	// tv2 = xd^2
	// gxd = tv2 * xd        # gxd = xd^3
	// gx1 = J * tv1         # x1n + J * xd
	// gx1 = gx1 * x1n       # x1n^2 + J * x1n * xd
	// gx1 = gx1 + tv2       # x1n^2 + J * x1n * xd + xd^2
	// gx1 = gx1 * x1n       # x1n^3 + J * x1n^2 * xd + x1n * xd^2
	// tv3 = gxd^2
	// tv2 = tv3^2           # gxd^4
	// tv3 = tv3 * gxd       # gxd^3
	// tv3 = tv3 * gx1       # gx1 * gxd^3
	// tv2 = tv2 * tv3       # gx1 * gxd^7
	// y11 = tv2^c4          # (gx1 * gxd^7)^((p - 5) / 8)
	// y11 = y11 * tv3       # gx1 * gxd^3 * (gx1 * gxd^7)^((p - 5) / 8)
	// y12 = y11 * c3
	// tv2 = y11^2
	// tv2 = tv2 * gxd
	//  e1 = tv2 == gx1
	//  y1 = CMOV(y12, y11, e1)  # If g(x1) is square, this is its sqrt
	// x2n = x1n * tv1           # x2 = x2n / xd = 2 * u^2 * x1n / xd
	// y21 = y11 * u
	// y21 = y21 * c2
	// y22 = y21 * c3
	// gx2 = gx1 * tv1           # g(x2) = gx2 / gxd = 2 * u^2 * g(x1)
	// tv2 = y21^2
	// tv2 = tv2 * gxd
	//  e2 = tv2 == gx2
	//  y2 = CMOV(y22, y21, e2)  # If g(x2) is square, this is its sqrt
	// tv2 = y1^2
	// tv2 = tv2 * gxd
	//  e3 = tv2 == gx1
	//  xn = CMOV(x2n, x1n, e3)  # If e3, x = x1, else x = x2
	//   y = CMOV(y2, y1, e3)    # If e3, y = y1, else y = y2
	//  e4 = sgn0(y) == 1        # Fix sign of y
	//   y = CMOV(y, -y, e3 XOR e4)
	// return (xn, xd, y, 1)

}
