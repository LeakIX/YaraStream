package YaraStream

import (
	"github.com/hillu/go-yara/v4"
	"io"
)

type YaraReader struct {
	yaraWriter *YaraWriter
}

func (s *YaraScanner) ScanReader(reader io.Reader, options ...func(writer *YaraWriter)) ([]*yara.Rule, error) {
	var err error
	r := &YaraReader{}
	r.yaraWriter = s.NewYaraWriter(options...)
	_, err = io.Copy(r.yaraWriter, reader)
	if err != nil {
		return r.yaraWriter.MatchedRules, err
	}
	err = r.yaraWriter.Close()
	if err != nil {
		return r.yaraWriter.MatchedRules, err
	}
	return r.yaraWriter.MatchedRules, err
}
