package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"github.com/LeakIX/YaraStream"
	"github.com/elvinchan/clamd"
	"io"
	"log"
	"os"
)

var (
	clamdSock = flag.String("clamd-sock", "", "ClamD socket")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatal("You must provide a file to scan")
	}
	clamClient, err := clamd.NewClient("unix", *clamdSock)
	if err != nil {
		panic(err)
	}
	scanner, err := YaraStream.NewYaraScanner(
		YaraStream.RuleDirectory{Namespace: "AbuseCH", Path: "./rules/abusech"},
		YaraStream.RuleDirectory{Namespace: "ReversingLabs", Path: "./rules/reversinglabs"},
		YaraStream.RuleDirectory{Namespace: "ESET", Path: "./rules/eset"},
	)
	if err != nil {
		panic(err)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	yaraWriter := scanner.NewYaraWriter()
	sha256Hasher := sha256.New()
	sha1Hasher := sha1.New()
	sha256Tee := io.TeeReader(file, sha256Hasher)
	sha1Tee := io.TeeReader(sha256Tee, sha1Hasher)
	yaraTee := YaraStream.TeeReaderAutoClose(sha1Tee, yaraWriter)
	scanResults, err := clamClient.ScanReader(context.Background(), yaraTee)
	if err != nil {
		panic(err)
	}
	infected := false
	for _, scanResult := range scanResults {
		if scanResult.Status == "FOUND" {
			infected = true
			log.Printf("[ClamAV] Infection found: %s", scanResult.Signature)
		}
	}
	for _, scanResult := range yaraWriter.MatchedRules {
		infected = true
		log.Printf("[YARA] Infection found: %s/%s", scanResult.Namespace(), scanResult.Identifier())
	}
	log.Printf("SHA256: %s", hex.EncodeToString(sha256Hasher.Sum(nil)))
	log.Printf("SHA1: %s", hex.EncodeToString(sha1Hasher.Sum(nil)))
	if infected {
		os.Exit(1)
	}
}
