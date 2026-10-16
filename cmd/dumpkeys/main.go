// Command dumpkeys prints a Java private-key file's destination and key types.
package main

import (
	"fmt"
	"os"

	"github.com/goose-network/i2p-go/internal/data"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	dest, rest, err := data.ReadDestination(raw)
	if err != nil {
		fmt.Println("parse destination:", err)
		os.Exit(1)
	}
	fmt.Printf("dest bytes=%d (file %d), enc=%d sig=%d\n", len(raw)-len(rest), len(raw), dest.EncType, dest.SigType)
	fmt.Printf("b32 %s\n", dest.Base32Address())
	fmt.Printf("after dest: %d bytes\n", len(rest))
	if len(rest) >= 64 {
		fmt.Printf("signing priv key: %s\n", data.EncodeToI2PBase64(rest[32:64]))
	}
}
