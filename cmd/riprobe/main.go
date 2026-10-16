// Command riprobe prints a RouterInfo file (diagnostic helper).
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	ri, err := data.ReadRouterInfo(raw, false)
	if err != nil {
		panic(err)
	}
	fmt.Printf("hash=%s published=%s ago\n", ri.RouterHash().ToI2PBase64(), time.Since(ri.Published).Round(time.Second))
	for _, a := range ri.Addresses {
		fmt.Printf("addr %s cost=%d opts=%v\n", a.TransportStyle, a.Cost, a.Options)
	}
	for k, v := range ri.Options {
		fmt.Printf("opt %s=%s\n", k, v)
	}
}
