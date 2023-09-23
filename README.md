# Yara scanner for Golang

Yara scanner library compatible with `io.Reader` for streaming

## Features

- Read multiple rules for multiple directories
- Scan inside archives with maximum depth

## Requirements

All requirements from [github.com/hillu/go-yara](https://github.com/hillu/go-yara) apply

## Example

```golang
package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"github.com/LeakIX/YaraStream"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var yaraScanner *YaraStream.YaraScanner
var fileChan = make(chan string)
var wg sync.WaitGroup

func main() {
	var err error
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatal("You must provide a file to scan")
	}
	yaraScanner, err = YaraStream.NewYaraScanner(
		YaraStream.RuleDirectory{Namespace: "AbuseCH", Path: "./rules/abusech"},
		YaraStream.RuleDirectory{Namespace: "ReversingLabs", Path: "./rules/reversinglabs"},
		YaraStream.RuleDirectory{Namespace: "ESET", Path: "./rules/eset"},
		YaraStream.RuleDirectory{Namespace: "AlienVault", Path: "./rules/otx"},
	)
	if err != nil {
		panic(err)
	}

	for w := 1; w <= runtime.NumCPU(); w++ {
		go worker()
	}
	err = filepath.Walk(flag.Arg(0), func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		wg.Add(1)
		fileChan <- path
		return nil
	})

	if err != nil {
		panic(err)
	}
	wg.Wait()
}

func worker() {
	for filePath := range fileChan {
		scanFile(filePath)
		wg.Done()
	}
}

func scanFile(path string) error {
	log.Printf("Scanning %s", path)
	file, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return nil
	}
	sha256Hasher := sha256.New()
	sha1Hasher := sha1.New()
	sha256Tee := io.TeeReader(file, sha256Hasher)
	sha1Tee := io.TeeReader(sha256Tee, sha1Hasher)
	matches, err := yaraScanner.ScanReader(sha1Tee, YaraStream.WithFilenameTip(path), YaraStream.WithMaxLevel(3))
	for _, scanResult := range matches {
		log.Printf("[YARA] Infection found: %s/%s in %s\n", scanResult.Namespace(), scanResult.Identifier(), path)
	}
	return nil
}

```
