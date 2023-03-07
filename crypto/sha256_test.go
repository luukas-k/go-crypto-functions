package crypto_test

import (
	"example/crypto"
	"testing"
)

func TestSha256(t *testing.T) {
	a := make([]uint8, 1000000)
	for i := 0; i < len(a); i++ {
		a[i] = 'a'
	}
	
	testVectors := [][]string{
		{
			"abc", 
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			string(a),
			"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
		},
	}
	for i := 0; i < len(testVectors); i++ {
		msg := testVectors[i][0]
		expectedHash := testVectors[i][1]
		hash := crypto.Sha256(msg)
		if hash != expectedHash {
			t.Errorf("\nHash:     %s\nExpected: %s\n", hash, expectedHash)
		}
	}
}
