package YaraStream

import (
	"bytes"
	"github.com/hillu/go-yara/v4"
)

func (s *YaraScanner) NewYaraWriter(maxMem int) *YaraWriter {
	writer := &YaraWriter{
		maxMem: maxMem,
	}
	writer.scanner, _ = yara.NewScanner(s.rules)
	writer.scanner.SetCallback(writer)
	return writer
}

type YaraWriter struct {
	buffer    bytes.Buffer
	scanner   *yara.Scanner
	Infected  bool
	Signature []string
	maxMem    int
}

func (y *YaraWriter) Write(p []byte) (n int, err error) {
	if y.Infected || y.buffer.Len() > y.maxMem {
		return len(p), nil
	}
	return y.buffer.Write(p)

}

func (y *YaraWriter) Close() (err error) {
	err = y.scanner.ScanMem(y.buffer.Bytes())
	y.scanner.Destroy()
	y.buffer.Reset()
	return err
}

func (y *YaraWriter) RuleMatching(context *yara.ScanContext, rule *yara.Rule) (bool, error) {
	y.Infected = true
	y.Signature = append(y.Signature, rule.Identifier())
	return true, nil
}
