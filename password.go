package gpswd

import (
	"database/sql/driver"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Password
type Password struct {
	plain  []byte
	salt   []byte
	cipher []byte
}

// NewPassword returns Password
func NewPassword(plain string, salt []byte) *Password {
	return &Password{
		plain: []byte(plain),
		salt:  salt,
	}
}

// Encrypt encrypts plain password
func (p *Password) Encrypt() error {
	if len(p.plain) == 0 {
		return ErrEmptyPassword
	}

	plainsalt, err := BeforeEncrypt(p.plain, p.salt)
	if err != nil {
		return err
	}

	// Generate hash
	hash, err := bcrypt.GenerateFromPassword(plainsalt, HashCost)
	if err != nil {
		return fmt.Errorf("generate hash failed: %w", err)
	}
	p.cipher = hash
	return nil
}

// Encrypted returns true if encrypted
func (p *Password) Encrypted() bool {
	return len(p.cipher) > 0
}

// Compare compares with password and returns nil if matched
func (p *Password) Compare(passwd string, salt []byte) error {
	if !p.Encrypted() {
		return ErrNotYetEncrypted
	}

	plainsalt, err := BeforeEncrypt([]byte(passwd), salt)
	if err != nil {
		return err
	}

	// Compare
	if err := bcrypt.CompareHashAndPassword(p.cipher, plainsalt); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrMismatched
		}
		return fmt.Errorf("bcrypt.CompareHashAndPassword: %w", err)
	}
	return nil
}

// Scan is an implementation interface sql.Scanner
func (p *Password) Scan(value any) error {
	bs, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("type assertion failed: value(any) to []byte")
	}
	p.cipher = bs
	return nil
}

// Value is an implementation interface driver.Valuer
func (p *Password) Value() (driver.Value, error) {
	if p.Encrypted() {
		return p.cipher, nil
	}

	if err := p.Encrypt(); err != nil {
		return nil, fmt.Errorf("p.Encrypt: %w", err)
	}
	return p.cipher, nil
}

// HashCost is cost of generating password hash
var HashCost = 12

// BeforeEncrypt is called before encryption
// and concats plain passwords and salt
var BeforeEncrypt = func(plain, salt []byte) ([]byte, error) {
	return append(plain, salt...), nil
}

var (
	ErrEmptyPassword   = errors.New("empty passowrd")
	ErrNotYetEncrypted = errors.New("not yet encrypted")
	ErrMismatched      = errors.New("mismatched password")
)
