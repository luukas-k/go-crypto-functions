package crypto_test

import (
	"example/crypto"
	"testing"
)

func TestSha512(t *testing.T) {
	testVectors := [][]string{
		{
			"abc", 
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		},
	}
	for i := 0; i < len(testVectors); i++ {
		msg := testVectors[i][0]
		expectedHash := testVectors[i][1]
		hash := crypto.Sha512(msg)
		if hash != expectedHash {
			t.Errorf("\nHash:     %s\nExpected: %s\n", hash, expectedHash)
		}
	}
}
