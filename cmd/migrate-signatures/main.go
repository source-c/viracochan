package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/source-c/viracochan"
)

func main() {
	var (
		dir        string
		privateKey string
		journal    string
		dryRun     bool
	)

	flag.StringVar(&dir, "dir", "", "storage root directory")
	flag.StringVar(&privateKey, "private-key", "", "hex-encoded private key used to re-sign configs")
	flag.StringVar(&journal, "journal", "journal.jsonl", "journal path relative to the storage root")
	flag.BoolVar(&dryRun, "dry-run", false, "report what would change without writing")
	flag.Parse()

	if dir == "" {
		fmt.Fprintln(os.Stderr, "-dir is required")
		os.Exit(2)
	}
	if privateKey == "" {
		fmt.Fprintln(os.Stderr, "-private-key is required")
		os.Exit(2)
	}

	storage, err := viracochan.NewFileStorage(dir)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := viracochan.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	manager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
		viracochan.WithJournalPath(journal),
	)
	if err != nil {
		log.Fatal(err)
	}

	report, err := manager.MigrateLegacySignatures(context.Background(), viracochan.SignatureMigrationOptions{
		DryRun: dryRun,
	})
	if err != nil {
		log.Fatal(err)
	}

	if dryRun {
		fmt.Println("dry-run: no files were modified")
	}
	fmt.Println(report.String())
}
