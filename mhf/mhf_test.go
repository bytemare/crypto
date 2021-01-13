package mhf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
)

var mhfs = []MHF{Argon2id, Scrypt, PBKDF2Sha512, Bcrypt}

func TestAvailability(t *testing.T) {
	for _, i := range mhfs {
		if !i.Available() {
			t.Errorf("%s is not available, but should be", i)
		}
	}

	wrong := 0
	if MHF(wrong).Available() {
		t.Errorf("%v is considered available when it should not", wrong)
	}
}

func TestMHF(t *testing.T) {
	password := []byte("password")
	salt := utils.RandomBytes(32)
	enc := encoding.JSON

	for _, m := range mhfs {
		t.Run(m.String(), func(t *testing.T) {
			p := m.DefaultParameters()

			assert.NotPanics(t, func() {
				_ = p.Hash(password, salt)
			})

			e, err := p.Encode(enc)
			if err != nil {
				t.Fatalf("%s : %v", p.ID, err)
			}

			p2, err := Decode(e, enc)
			if err != nil {
				t.Fatalf("%s : %v", p.ID, err)
			}

			assert.Equal(t, p, p2)
		})
	}
}
