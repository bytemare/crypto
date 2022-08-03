package nist

type nistECPoint[point any] interface {
	Add(p1, p2 point) point
	BytesCompressed() []byte
	Double(p point) point
	ScalarBaseMult(scalar []byte) (point, error)
	ScalarMult(p point, scalar []byte) (point, error)
	Bytes() []byte
	Select(p1, p2 point, cond int) point
	Set(p point) point
	SetBytes(b []byte) (point, error)
	SetGenerator() point
}
