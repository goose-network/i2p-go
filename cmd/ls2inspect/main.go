// Command ls2inspect prints a dumped LeaseSet2's destination, keys, and
// leases. With -dest it prints just the base64 destination (one line,
// addressbook hosts.txt format).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/goose-network/i2p-go/internal/data"
)

func main() {
	destOnly := flag.Bool("dest", false, "print only the base64 destination")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Println("usage: ls2inspect [-dest] <leaseset-file>")
		os.Exit(1)
	}
	raw, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	ls, err := data.ReadLeaseSet2(raw, true)
	if err != nil {
		fmt.Println("parse+verify:", err)
		os.Exit(1)
	}
	// The destination is the file's leading bytes (ReadLeaseSet2 has
	// parsed them out of ls.raw).
	if *destOnly {
		_, rest, _ := data.ReadDestination(raw)
		fmt.Println(data.EncodeToI2PBase64(raw[:len(raw)-len(rest)]))
		return
	}
	fmt.Printf("dest sig=%d enc=%d flags=0x%04x\n",
		ls.Destination.SigType, ls.Destination.EncType, ls.Flags)
	fmt.Printf("published %s ago, expires in %s\n",
		time.Since(ls.Published).Round(time.Second),
		time.Until(ls.Expires).Round(time.Second))
	fmt.Printf("options: %v\n", ls.Options)
	for _, k := range ls.EncryptionKeys {
		fmt.Printf("enc key: type=%d elg=%v len=%d\n", k.EncType, k.ElGamal, len(k.Key))
	}
	for i, l := range ls.Leases {
		fmt.Printf("lease %d: gw=%s tid=%d end in %s\n", i,
			l.Gateway.ToI2PBase64()[:12], l.TunnelID,
			time.Until(l.End).Round(time.Second))
	}
}
