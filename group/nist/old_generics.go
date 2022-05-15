package internal

//type GenericGroup[GE OldGenericElement[GE], Scalar GenericScalar[Scalar]] interface {
//	NewScalar() Scalar
//	NewElement() GE
//}

type OldGenericElement[GE any] interface {
	Add(p1, p2 GE) GE
	Bytes() []byte
	Double(p GE) GE
	ScalarBaseMult(scalar []byte) (GE, error)
	ScalarMult(p GE, scalar []byte) (GE, error)
	Select(p1, p2 GE, cond int) GE
	Set(p GE) GE
	SetBytes(b []byte) (GE, error)
	SetGenerator() GE
}

//type GenericScalar[Scalar any] interface {
//	Zero() Scalar
//}
