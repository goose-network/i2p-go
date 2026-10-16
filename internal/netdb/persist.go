// NetDB disk persistence in the i2pd on-disk format: one
// uncompressed RouterInfo per file named
// netDb/r<first-char>/routerInfo-<b64 router hash>.dat. This makes our
// netdb directory interoperable with i2pd's and lets the floodfill
// set survive restarts without reseeding.
//
// Reference: i2pd NetDb.cpp (m_Storage("netDb", "r", "routerInfo-",
// "dat"), PersistRouters → RouterInfo::SaveToFile) and
// base64-substitution filenames.
package netdb

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/goose-network/i2p-go/internal/data"
)

// Persist writes every stored RI and LeaseSet2 into dir (i2pd netDb
// layout for RIs; LeaseSets are flat leaseSet-<hash>.dat files, the
// Java netDb layout — i2pd keeps LeaseSets in memory only).
func (n *NetDB) Persist(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, ri := range n.AllRouters() {
		name := ri.NetDBFileName()
		// r<first char of the b64 hash>/routerInfo-<hash>.dat
		sub := filepath.Join(dir, "r"+string(name[0]))
		if err := os.MkdirAll(sub, 0o755); err != nil {
			return err
		}
		file := filepath.Join(sub, "routerInfo-"+name+".dat")
		if err := os.WriteFile(file, ri.Bytes(), 0o644); err != nil {
			return err
		}
	}
	for _, ls := range n.AllLS2s() {
		name := data.DestinationHash(ls.Destination).ToI2PBase64()
		file := filepath.Join(dir, "leaseSet-"+name+".dat")
		if err := os.WriteFile(file, ls.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadPersisted reads an i2pd-format netDb directory into the store:
// routerInfo-*.dat under r<first-char> subdirectories and flat
// leaseSet-*.dat files. It is best-effort per file: bad entries are
// skipped.
func LoadPersisted(dir string, db *NetDB) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			if strings.HasPrefix(e.Name(), "leaseSet-") && strings.HasSuffix(e.Name(), ".dat") {
				raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					continue
				}
				ls, err := data.ReadLeaseSet2(raw, false)
				if err != nil {
					continue
				}
				db.StoreLS2(ls)
				n++
			}
			continue
		}
		if !strings.HasPrefix(e.Name(), "r") {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasPrefix(f.Name(), "routerInfo-") || !strings.HasSuffix(f.Name(), ".dat") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name(), f.Name()))
			if err != nil {
				continue
			}
			ri, err := data.ReadRouterInfo(raw, false)
			if err != nil {
				continue
			}
			db.StoreRI(&ri)
			n++
		}
	}
	return n, nil
}
