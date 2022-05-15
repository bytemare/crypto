package test

import (
	"encoding/hex"
	nistec2 "filippo.io/nistec"
	"github.com/bytemare/crypto/group/internal"
	"github.com/bytemare/crypto/group/old/internal/nistec"
	"log"
	"testing"
)

type Point[P internal.OldGenericElement[P]] struct {
	p P
}

func NewP256Point() *Point[*nistec2.P256Point] {
	return &Point[*nistec2.P256Point]{p: nistec2.NewP256Point()}
}

func (p *Point[P]) Add(q *Point[P]) *Point[P] {
	p.p.Add(p.p, q.p)

	return p
}

func (p *Point[P]) Bytes() []byte {
	return p.p.Bytes()
}

type NistPoint struct {
	p *nistec2.P256Point
}

func NewNist256Point() *NistPoint {
	return &NistPoint{p: nistec2.NewP256Point()}
}

func (p *NistPoint) Add(p1, p2 *NistPoint) *NistPoint {
	p.p.Add(p1.p, p2.p)
	//Add(p.p, p1.p, p2.p)
	return p
}

func (p *NistPoint) Bytes() []byte {
	return p.p.Bytes()
}

func (p *NistPoint) Double(q *NistPoint) *NistPoint {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) ScalarBaseMult(scalar []byte) (*NistPoint, error) {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) ScalarMult(q *NistPoint, scalar []byte) (*NistPoint, error) {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) Select(p1, p2 *NistPoint, cond int) *NistPoint {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) Set(q *NistPoint) *NistPoint {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) SetBytes(b []byte) (*NistPoint, error) {
	//TODO implement me
	panic("implement me")
}

func (p *NistPoint) SetGenerator() *NistPoint {
	//TODO implement me
	panic("implement me")
}

//func Add[GE internal.OldGenericElement[GE]](e, e1, e2 GE) GE {
//	return e.Add(e1, e2)
//}

func TestAdd(t *testing.T) {
	p := nistec.NewMyP256Point()
	p1 := nistec.NewMyP256Point()
	p2 := nistec.NewMyP256Point()

	log.Println(hex.EncodeToString(p.Add(p1, p2).Bytes()))
}

func TestAdd2(t *testing.T) {
	p := nistec2.NewP256Point()
	p1 := nistec2.NewP256Point()
	p2 := nistec2.NewP256Point()

	log.Println(hex.EncodeToString(p.Add(p1, p2).Bytes()))
}

func TestAdd3(t *testing.T) {
	p := NewP256Point()
	p1 := NewP256Point()

	log.Println(hex.EncodeToString(p.Add(p1).Bytes()))
}
