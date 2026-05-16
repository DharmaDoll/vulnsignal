package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

type metadata struct {
	Version int `json:"Version"`
}

type dumpRecord struct {
	RowType     string          `json:"row_type"`
	VulnID      string          `json:"vuln_id"`
	PackageName string          `json:"package_name,omitempty"`
	SourcePath  []string        `json:"source_path,omitempty"`
	PayloadHash string          `json:"payload_hash,omitempty"`
	Payload     json.RawMessage `json:"payload"`
}

func payloadHash(payload json.RawMessage) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

func readMetadata(dbDir string) (metadata, error) {
	path := filepath.Join(dbDir, "metadata.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return metadata{}, err
	}
	return meta, nil
}

func emitBucketLeaves(enc *json.Encoder, bkt *bolt.Bucket, vulnID string, path []string) error {
	if bkt == nil {
		return nil
	}
	return bkt.ForEach(func(k, v []byte) error {
		if v == nil {
			return emitBucketLeaves(enc, bkt.Bucket(k), vulnID, append(path, string(k)))
		}
		if !json.Valid(v) {
			return fmt.Errorf("invalid json payload for %s/%s", vulnID, string(k))
		}
		record := dumpRecord{
			RowType:     "advisory",
			VulnID:      vulnID,
			PackageName: string(k),
			SourcePath:  append([]string(nil), path[1:]...),
			PayloadHash: payloadHash(v),
			Payload:     json.RawMessage(v),
		}
		return enc.Encode(record)
	})
}

func dumpTrivyDB(dbDir string) error {
	dbPath := filepath.Join(dbDir, "trivy.db")
	db, err := bolt.Open(dbPath, 0o644, &bolt.Options{ReadOnly: true})
	if err != nil {
		return err
	}
	defer db.Close()

	return db.View(func(tx *bolt.Tx) error {
		enc := json.NewEncoder(os.Stdout)

		if bkt := tx.Bucket([]byte("vulnerability")); bkt != nil {
			if err := bkt.ForEach(func(k, v []byte) error {
				if v == nil || !json.Valid(v) {
					return nil
				}
				return enc.Encode(dumpRecord{
					RowType:     "vulnerability",
					VulnID:      string(k),
					PayloadHash: payloadHash(v),
					Payload:     json.RawMessage(v),
				})
			}); err != nil {
				return err
			}
		}

		root := tx.Bucket([]byte("advisory-detail"))
		if root == nil {
			return nil
		}

		return root.ForEach(func(k, v []byte) error {
			if v != nil {
				return nil
			}
			vulnID := string(k)
			return emitBucketLeaves(enc, root.Bucket(k), vulnID, []string{vulnID})
		})
	})
}

func main() {
	dbDir := flag.String("db-dir", "", "Path to a Trivy DB cache directory.")
	expected := flag.Int("expected-schema-version", 2, "Expected metadata.json Version.")
	flag.Parse()

	if *dbDir == "" {
		fmt.Fprintln(os.Stderr, "missing --db-dir")
		os.Exit(2)
	}

	meta, err := readMetadata(*dbDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if meta.Version != *expected {
		fmt.Fprintf(os.Stderr, "trivy db schema version mismatch: got %d want %d\n", meta.Version, *expected)
		os.Exit(1)
	}

	if err := dumpTrivyDB(*dbDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
