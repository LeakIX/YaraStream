package YaraStream

import (
	"github.com/hillu/go-yara/v4"
)

type YaraWriter struct {
	scanner      *yara.Scanner
	Infected     bool
	Signature    []string
	writeChannel chan []byte
	doneChannel  chan error
	byteCount    uint64
	firstBlock   *yara.MemoryBlock
}

func (s *YaraScanner) NewYaraWriter() *YaraWriter {
	writer := &YaraWriter{}
	writer.scanner, _ = yara.NewScanner(s.rules)
	writer.scanner.SetCallback(writer)
	writer.writeChannel = make(chan []byte)
	writer.doneChannel = make(chan error)
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
	y.writeChannel <- p
	return len(p), nil
}

func (y *YaraWriter) Close() (err error) {
	close(y.writeChannel)
	err = <-y.doneChannel
	y.scanner.Destroy()
	return err
}

func (y *YaraWriter) RuleMatching(context *yara.ScanContext, rule *yara.Rule) (bool, error) {
	y.Infected = true
	y.Signature = append(y.Signature, rule.Identifier())
	return true, nil
}
