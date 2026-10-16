// Command b32check prints a base64 destination's b32 hostname and key
// types (diagnostic helper; also used to pin destination-hash bugs).
package main

import (
	"fmt"
	"os"

	"github.com/goose-network/i2p-go/internal/data"
)

func main() {
	for _, arg := range os.Args[1:] {
		raw, err := data.DecodeI2PBase64(arg)
		if err != nil {
			fmt.Println("decode:", err)
			os.Exit(1)
		}
		dest, _, err := data.ReadDestination(raw)
		if err != nil {
			fmt.Println("parse destination:", err)
			os.Exit(1)
		}
		fmt.Printf("b32 %s enc=%d sig=%d\n", dest.Base32Address(), dest.EncType, dest.SigType)
	}
}
