package encoding

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestI2OSP(t *testing.T) {
	good := map[int]string{
		0:     "00",
		1:     "01",
		255:   "ff",
		256:   "0100",
		65535: "ffff",
	}

	for k, v := range good {
		r := I2OSP(k)

		if hex.EncodeToString(r) != v {
			t.Fatalf("invalid encoding for %d. Expected '%s', got '%v'", k, v, hex.EncodeToString(r))
		}
	}

	negative := -1
	tooLarge := 1 << 32

	assert.PanicsWithError(t, errI2OSPNegative.Error(), func() {
		_ = I2OSP(negative)
	}, "expected panic with negative value")

	assert.PanicsWithError(t, errI2OSPLarge.Error(), func() {
		_ = I2OSP(tooLarge)
	}, "expected panic with big value")

	lengths := map[int]int{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := I2OSP(k)

		if len(r) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}
