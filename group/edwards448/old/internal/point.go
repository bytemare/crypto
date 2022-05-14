package internal

import "github.com/bytemare/crypto/group/edwards448/internal/field"

type Point struct {
	curve *Curve
	x     *field.Element
	y     *field.Element
}
