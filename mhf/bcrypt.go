package mhf

import (
	"golang.org/x/crypto/bcrypt"
)

const (
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

func bcryptParams() *Parameters {
	return &Parameters{
		ID:        Bcrypt,
		Time:      defaultBcryptCost,
		Memory:    0,
		Threads:   0,
		KeyLength: 0,
	}
}
