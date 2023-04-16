// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package h2c provides hash-to-curve primitives and mapping.
package h2c

import (
	"math/big"

	"github.com/bytemare/crypto/internal/field"
)

// MapToCurveSSWU implements the Simplified SWU method for Weierstrass curves for any base field.
func MapToCurveSSWU(f *field.Field, a, b, z, fe *big.Int) (x, y *big.Int) {
	var tv1, tv2, tv3, tv4, tv5, tv6, _y1, _px, _py big.Int

	f.Square(&tv1, fe)         //    1.  tv1 = u^2
	f.Mul(&tv1, z, &tv1)       //    2.  tv1 = Z * tv1
	f.Square(&tv2, &tv1)       //    3.  tv2 = tv1^2
	f.Add(&tv2, &tv2, &tv1)    //    4.  tv2 = tv2 + tv1
	f.Add(&tv3, &tv2, f.One()) //    5.  tv3 = tv2 + 1
	f.Mul(&tv3, b, &tv3)       //    6.  tv3 = B * tv3
	f.CondMov(&tv4, z,
		f.Neg(&big.Int{}, &tv2),
		!f.IsZero(&tv2)) //    7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	f.Mul(&tv4, a, &tv4)                               //    8.  tv4 = A * tv4
	f.Square(&tv2, &tv3)                               //    9.  tv2 = tv3^2
	f.Square(&tv6, &tv4)                               //    10. tv6 = tv4^2
	f.Mul(&tv5, a, &tv6)                               //    11. tv5 = A * tv6
	f.Add(&tv2, &tv2, &tv5)                            //    12. tv2 = tv2 + tv5
	f.Mul(&tv2, &tv2, &tv3)                            //    13. tv2 = tv2 * tv3
	f.Mul(&tv6, &tv6, &tv4)                            //    14. tv6 = tv6 * tv4
	f.Mul(&tv5, b, &tv6)                               //    15. tv5 = B * tv6
	f.Add(&tv2, &tv2, &tv5)                            //    16. tv2 = tv2 + tv5
	f.Mul(&_px, &tv1, &tv3)                            //    17.   x = tv1 * tv3
	isGx1Square := f.SqrtRatio(&_y1, z, &tv2, &tv6)    //    18. isGx1Square, y1 = sqrt_ratio(tv2, tv6)
	f.Mul(&_py, &tv1, fe)                              //    19.   y = tv1 * u
	f.Mul(&_py, &_py, &_y1)                            //    20.   y = y * y1
	f.CondMov(&_px, &_px, &tv3, isGx1Square)           //    21.   x = CMOV(x, tv3, isGx1Square)
	f.CondMov(&_py, &_py, &_y1, isGx1Square)           //    22.   y = CMOV(y, y1, isGx1Square)
	e1 := f.Sgn0(fe) == f.Sgn0(&_py)                   //    23.  e1 = sgn0(u) == sgn0(y)
	f.CondMov(&_py, f.Neg(&big.Int{}, &_py), &_py, e1) //    24.   y = CMOV(-y, y, e1)
	f.Inv(&tv4, &tv4)                                  //    25.   1 / tv4
	f.Mul(&_px, &_px, &tv4)                            //	 26.   x = x / tv4

	return &_px, &_py
}
