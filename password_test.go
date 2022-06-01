package gpswd

import (
	"database/sql"
	"errors"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestPassword_Encrypt(t *testing.T) {
	testCases := []struct {
		Password string
		Salt     []byte
		Want     error
	}{
		{"password", []byte("salt"), nil},
		{"", []byte("salt"), ErrEmptyPassword},
	}

	for _, tc := range testCases {
		p := NewPassword(tc.Password, tc.Salt)

		err := p.Encrypt()
		if !errors.Is(err, tc.Want) {
			t.Errorf("err = %v, want = %v", err, tc.Want)
		}
	}
}

func TestPassword_Compare(t *testing.T) {
	testCases := []struct {
		Password        string
		Salt            []byte
		ComparePassword string
		CompareSalt     []byte
		Want            error
	}{
		{
			"password", []byte("salt"),
			"password", []byte("salt"),
			nil,
		},
		{
			"password", []byte("salt"),
			"passw0rd", []byte("salt"),
			ErrMismatched,
		},
		{
			"password", []byte("salt"),
			"password", []byte("saIt"),
			ErrMismatched,
		},
	}

	for _, tc := range testCases {
		p := NewPassword(tc.Password, tc.Salt)

		if err := p.Encrypt(); err != nil {
			t.Fatalf("p.Encrypt: %v", err)
		}

		err := p.Compare(tc.ComparePassword, tc.CompareSalt)
		if !errors.Is(err, tc.Want) {
			t.Errorf("err = %v, want = %v", err, tc.Want)
		}
	}
}

func TestPassword_Scan_Value(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed open sqlite database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE passwords (password BLOB)")
	if err != nil {
		t.Errorf("failed create table passwords: %v", err)
		return
	}

	p := NewPassword("password", []byte("salt"))
	_, err = db.Exec("INSERT INTO passwords (password) VALUES (?)", p)
	if err != nil {
		t.Errorf("failed insert into passwords: %v", err)
		return
	}

	row := db.QueryRow("SELECT * FROM passwords")
	pFromDB := new(Password)
	err = row.Scan(pFromDB)
	if err != nil {
		t.Errorf("failed scan row: %v", err)
		return
	}

	if !reflect.DeepEqual(p.cipher, pFromDB.cipher) {
		t.Errorf("p.ciper not equal pFromDB.cipher: p=%v pFromDB=%v", p.cipher, pFromDB.cipher)
	}
}
