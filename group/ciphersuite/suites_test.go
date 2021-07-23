package ciphersuite

import (
	"testing"
)

const testVersion = "0.0"

//func TestNilDST(t *testing.T) {
//	for s := range registered {
//		t.Run(s.String(), func(t *testing.T) {
//			var g group.Group
//
//			// Nil DST
//			var dst []byte
//			assert.NotPanics(t, func() {
//				g = s.Get(dst)
//			}, "unexpected panic")
//
//			assert.PanicsWithError(t, internal.ParameterError("zero-length DST").Error(), func() {
//				_ = g.HashToGroup(nil, nil)
//			})
//
//			assert.PanicsWithError(t, internal.ParameterError("zero-length DST").Error(), func() {
//				_ = g.HashToScalar(nil, nil)
//			})
//		})
//	}
//}

//func TestShortDST(t *testing.T) {
//	for s := range registered {
//		t.Run(s.String(), func(t *testing.T) {
//			var g group.Group
//
//			// Short DST
//			dst := []byte("short")
//			assert.NotPanics(t, func() {
//				g = s.Get(dst)
//			}, "unexpected panic")
//
//			assert.PanicsWithError(t, internal.ParameterError("DST is shorter than recommended length").Error(), func() {
//				_ = g.HashToGroup(nil, dst)
//			})
//
//			assert.PanicsWithError(t, internal.ParameterError("DST is shorter than recommended length").Error(), func() {
//				_ = g.HashToScalar(nil, dst)
//			})
//		})
//	}
//}

func TestAvailability(t *testing.T) {
	for id := range registered {
		if !id.Available() {
			t.Errorf("'%s' is not available, but should be", id.String())
		}
	}

	wrong := maxID
	if wrong.Available() {
		t.Errorf("%v is considered available when it must not", wrong)
	}
}
