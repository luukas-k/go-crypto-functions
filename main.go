package main

import (
	"example/crypto"
	"fmt"
)

func main() {
	fmt.Println(crypto.Sha256("abc"))
	fmt.Println(crypto.Sha512("abc"))
}