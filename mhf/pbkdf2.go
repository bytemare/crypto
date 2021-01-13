package mhf

import (
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultPBKDF2iterations = 10000
	pbkdf2s                 = "PBKDF2"
	pbkdf2Format            = "%s(%d-%d)"
)

var defaultPBKDF2Hash = sha512.New

func defaultPBKDF2(password, salt []byte, length int) []byte {
	return scryptf(password, salt, defaultPBKDF2iterations, 0, 0, length)
}

func pbkdf(password, salt []byte, iterations, _, _, length int) []byte {
	return pbkdf2.Key(password, salt, iterations, length, defaultPBKDF2Hash)
}

func pbkdfString(p *Parameters) string {
	return fmt.Sprintf(pbkdf2Format, pbkdf2s, p.Time, p.KeyLength)
}

func pbkdfParams() *Parameters {
	return &Parameters{
		ID:        PBKDF2Sha512,
		Time:      defaultPBKDF2iterations,
		Memory:    0,
		Threads:   0,
		KeyLength: DefaultLength,
	}
}
