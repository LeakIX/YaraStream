package YaraStream

import (
	"github.com/LeakIX/YaraStream/decoder"
	"github.com/hillu/go-yara/v4"
	"io"
)

type YaraWriter struct {
	scanner       *yara.Scanner
	Infected      bool
	MatchedRules  []*yara.Rule
	writeChannel  chan []byte
	doneChannel   chan error
	byteCount     uint64
	firstBlock    *yara.MemoryBlock
	MimeType      string
	parentScanner *YaraScanner
	childWriter   *io.PipeWriter
	childDoneChan chan error
	filename      string
	level         int
}

func (s *YaraScanner) NewYaraWriter(options ...func(writer *YaraWriter)) *YaraWriter {
	writer := &YaraWriter{
		parentScanner: s,
		writeChannel:  make(chan []byte),
		doneChannel:   make(chan error),
		childDoneChan: make(chan error),
	}
	for _, option := range options {
		option(writer)
	}
	writer.scanner, _ = yara.NewScanner(s.rules)
	writer.scanner.SetCallback(writer)
	go func() {
		writer.doneChannel <- writer.scanner.ScanMemBlocks(writer)
	}()
	return writer
}

func (y *YaraWriter) First() *yara.MemoryBlock {
	if y.firstBlock == nil {
		y.firstBlock = y.Next()
	}
	return y.firstBlock
}

func (y *YaraWriter) Next() *yara.MemoryBlock {
	// We work with 16K blocks to give more chances to First()
	var blockData []byte
	for {
		data, open := <-y.writeChannel
		if open {
			blockData = append(blockData, data...)
		}
		if len(blockData) >= 16*1024 || !open {
			break
		}
	}
	if len(blockData) == 0 {
		return nil
	}
	mb := &yara.MemoryBlock{
		Base:      y.byteCount,
		Size:      uint64(len(blockData)),
		FetchData: func(buf []byte) { copy(buf, blockData) },
	}
	y.byteCount += mb.Size
	return mb
}

func (y *YaraWriter) Write(p []byte) (n int, err error) {
	if y.childWriter == nil && y.level < 10 {
		y.exploreContainer()
	}
	if y.childWriter != nil {
		y.childWriter.Write(p)
	}
	y.writeChannel <- p
	return len(p), nil
}

func (y *YaraWriter) exploreContainer() {
	var pipeReader io.Reader
	pipeReader, y.childWriter = io.Pipe()
	go y.startContainerScan(pipeReader)
}

func (y *YaraWriter) startContainerScan(reader io.Reader) {
	dec, err := decoder.GetDecoder(y.filename, reader)
	if err != nil {
		io.Copy(io.Discard, reader)
		if err == decoder.ErrNotSupported {
			y.childDoneChan <- nil
		}
		y.childDoneChan <- err
		return
	}
	for {
		entry, err := dec.Next()
		if err != nil {
			io.Copy(io.Discard, reader)
			y.childDoneChan <- err
			return
		}
		if !entry.IsFile() {
			continue
		}
		matchedRules, err := y.parentScanner.ScanReader(dec, WithFilenameTip(entry.Filename), withCurrentLevel(y.level+1))
		if err != nil {
			continue
		}
		y.MatchedRules = append(y.MatchedRules, matchedRules...)
	}
}

func (y *YaraWriter) Close() (err error) {
	if y.childWriter != nil {
		y.childWriter.Close()
		<-y.childDoneChan
	}
	close(y.writeChannel)
	err = <-y.doneChannel
	y.scanner.Destroy()
	return err
}

func (y *YaraWriter) RuleMatching(context *yara.ScanContext, rule *yara.Rule) (bool, error) {
	y.Infected = true
	y.MatchedRules = append(y.MatchedRules, rule)
	return true, nil
}

func WithFilenameTip(filename string) func(writer *YaraWriter) {
	return func(writer *YaraWriter) {
		writer.filename = filename
	}
}

func withCurrentLevel(level int) func(writer *YaraWriter) {
	return func(writer *YaraWriter) {
		writer.level = level
	}
}
