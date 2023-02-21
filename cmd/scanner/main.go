package main

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/LeakIX/YaraStream"
	"github.com/elvinchan/clamd"
	"github.com/schollz/progressbar/v3"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

var (
	clamdSock = flag.String("clamd-sock", "", "ClamD socket")
)

var bar *progressbar.ProgressBar
var clamClient *clamd.Client
var yaraScanner *YaraStream.YaraScanner
var fileChan = make(chan string)
var wg sync.WaitGroup

func main() {
	var err error
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatal("You must provide a file to scan")
	}
	clamClient, err = clamd.NewClient("unix", *clamdSock)
	if err != nil {
		panic(err)
	}
	yaraScanner, err = YaraStream.NewYaraScanner(
		YaraStream.RuleDirectory{Namespace: "AbuseCH", Path: "./rules/abusech"},
		YaraStream.RuleDirectory{Namespace: "ReversingLabs", Path: "./rules/reversinglabs"},
		YaraStream.RuleDirectory{Namespace: "ESET", Path: "./rules/eset"},
	)
	if err != nil {
		panic(err)
	}
	bar = progressbar.NewOptions64(
		-1,
		progressbar.OptionSetDescription("Starting scanner..."),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionShowDescriptionAtLineEnd(),
	)
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
		wg.Add(1)
		scanFile(filePath)
		wg.Done()
	}
}

func scanFile(path string) error {
	bar.Describe(fmt.Sprintf("Scanning %s", path))
	file, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return nil
	}
	yaraWriter := yaraScanner.NewYaraWriter(YaraStream.WithFilenameTip(file.Name()))
	sha256Hasher := sha256.New()
	sha1Hasher := sha1.New()
	barTee := io.TeeReader(file, bar)
	sha256Tee := io.TeeReader(barTee, sha256Hasher)
	sha1Tee := io.TeeReader(sha256Tee, sha1Hasher)
	yaraTee := YaraStream.TeeReaderAutoClose(sha1Tee, yaraWriter)
	scanResults, err := clamClient.ScanReader(context.Background(), yaraTee)
	if err != nil {
		io.Copy(io.Discard, yaraTee)
	}
	for _, scanResult := range scanResults {
		if scanResult.Status == "FOUND" {
			fmt.Printf("[ClamAV] Infection found: %s in %s\n", scanResult.Signature, path)
		}
	}
	for _, scanResult := range yaraWriter.MatchedRules {
		fmt.Printf("[YARA] Infection found: %s/%s in %s\n", scanResult.Namespace(), scanResult.Identifier(), path)
	}
	return nil
}
