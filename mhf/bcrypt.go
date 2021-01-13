package mhf

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptFormat      = "%s(%d)"
	bcrypts           = "Bcrypt"
	defaultBcryptCost = 10
)

func defaultBcrypt(password, _ []byte, _ int) []byte {
	return bcryptf(password, nil, defaultBcryptCost, 0, 0, 0)
}

func bcryptf(password, _ []byte, time, _, _, _ int) []byte {
	h, err := bcrypt.GenerateFromPassword(password, time)
	if err != nil {
		panic(err)
	}

	return h
}

func bcryptString(p *Parameters) string {
	return fmt.Sprintf(bcryptFormat, bcrypts, p.Time)
}

func bcryptParams() *Parameters {
	return &Parameters{
		ID:        Bcrypt,
		Time:      defaultBcryptCost,
		Memory:    0,
		Threads:   0,
		KeyLength: 0,
	}
}
