package hashtogroup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testApp     = "testRistretto255"
	testVersion = "0.0"
)

func TestIdentifier_Get(t *testing.T) {
	for k := range registered {
		t.Run(string(k), func(t *testing.T) {
			assert.NotPanics(t, func() {
				dst, err := k.MakeDST(testApp, testVersion)
				if err == nil {
					panic(err)
				}
				k.Get(dst)
			}, "unexpected panic")
		})
	}
}

func TestAvailability(t *testing.T) {
	for id := range registered {
		if !id.Available() {
			t.Errorf("%v is not available, but should be", id)
		}
	}

	wrong := maxID
	if wrong.Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}
