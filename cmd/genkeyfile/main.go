// Command genkeyfile writes a Java-I2P-format private key file whose
// destination is ECIES (EncType 4) + Ed25519 — unlike
// I2PClientImpl.createDestination, which always creates ElGamal
// destinations. For an EncType 4 destination the destination's own
// X25519 key is the ECIES-Ratchet static key, so the ratchet public
// key is knowable from the file and a matching LeaseSet2 can be built
// offline (see cmd/ls2inject).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"github.com/goose-network/i2p-go/internal/data"
	"golang.org/x/crypto/curve25519"
)

func main() {
	out := flag.String("out", "", "output key file (Java PrivateKeyFile format)")
	flag.Parse()
	if *out == "" {
		fmt.Println("usage: genkeyfile -out <file>")
		os.Exit(1)
	}

	_, sp, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var gp [32]byte
	if _, err := rand.Read(gp[:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	xpub, err := curve25519.X25519(gp[:], curve25519.Basepoint)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	dest := &data.Destination{
		EncKey:     xpub,
		SigningKey: sp.Public().(ed25519.PublicKey),
		SigType:    data.SigEdDSA_SHA512_Ed25519,
		EncType:    data.EncECIES_X25519,
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// PrivateKeyFile.write(): destination, PrivateKey (32 bytes for
	// EncType 4), SigningPrivateKey (32-byte Ed25519 seed).
	if _, err := f.Write(dest.WriteTo(nil)); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if _, err := f.Write(gp[:]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if _, err := f.Write(sp[:32]); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("b32 %s\n", dest.Base32Address())
	fmt.Printf("destb64 %s\n", data.EncodeToI2PBase64(dest.WriteTo(nil)))
	fmt.Printf("x25519priv %s\n", data.EncodeToI2PBase64(gp[:]))
	fmt.Printf("ed25519priv %s\n", data.EncodeToI2PBase64(sp[:32]))
}
