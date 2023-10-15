package YaraStream

import (
	"bufio"
	"github.com/LeakIX/YaraStream/decoder"
	"github.com/hillu/go-yara/v4"
	"io"
)

type YaraReader struct {
	offset         int
	buf            []byte
	length         int
	r              *bufio.Reader
	scanner        *yara.Scanner
	mrs            []*yara.Rule
	firstBlock     *yara.MemoryBlock
	firstBlockData []byte
	firstBlockLen  int
	Infected       bool
	filename       string
	level          int
	maxBlockSize   int
	yaraVars       map[string]string
}

type YaraReaderOpt func(writer *YaraReader)

// ScanReader Will scan a given reader until EOF or an error happens. It will scan archives.
func (s *YaraScanner) ScanReader(reader io.Reader, opts ...YaraReaderOpt) ([]*yara.Rule, error) {
	testReader := &YaraReader{
		level:        10,
		maxBlockSize: 16 * 1024,
		yaraVars:     make(map[string]string),
	}
	for _, option := range opts {
		option(testReader)
	}
	testReader.r = bufio.NewReaderSize(reader, testReader.maxBlockSize)
	dec, err := decoder.GetDecoder(testReader.filename, testReader.r)
	if err == nil {
		if testReader.level < 1 {
			return nil, nil
		}
		for {
			entry, err := dec.Next()
			if err != nil || entry == nil {
				return testReader.mrs, nil
			}
			if entry.IsFile() {
				partResults, _ := s.ScanReader(dec,
					WithFilenameTip(entry.Filename),
					WithMaxLevel(testReader.level-1),
					WithBlockSize(testReader.maxBlockSize),
				)
				testReader.mrs = append(testReader.mrs, partResults...)
			}
		}
	}
	testReader.scanner, _ = yara.NewScanner(s.rules)
	defer testReader.scanner.Destroy()
	testReader.scanner.SetFlags(yara.ScanFlagsProcessMemory)
	testReader.scanner.SetCallback(testReader)
	for varKey, varValue := range testReader.yaraVars {
		err = testReader.scanner.DefineVariable(varKey, varValue)
		if err != nil {
			return nil, err
		}
	}
	testReader.buf = make([]byte, testReader.maxBlockSize)
	testReader.firstBlockData = make([]byte, testReader.maxBlockSize)
	err = testReader.scanner.ScanMemBlocks(testReader)

	return testReader.mrs, err
}

// First Will fetch the first block and cache it in our reader for further calls
func (s *YaraReader) First() *yara.MemoryBlock {
	if s.firstBlock == nil {
		s.firstBlock = s.Next()
		if s.firstBlock == nil {
			return nil
		}
		s.firstBlock.FetchData = s.first
		s.firstBlockLen = s.length
		copy(s.firstBlockData, s.buf)
	}
	return s.firstBlock
}

// Next Will fetch the next block for scanning
func (s *YaraReader) Next() *yara.MemoryBlock {
	n, err := s.r.Read(s.buf)
	if err != nil && n == 0 {
		return nil
	}
	s.offset += n
	s.length = n
	return &yara.MemoryBlock{
		Base:      uint64(s.offset - n),
		Size:      uint64(n),
		FetchData: s.copy,
	}
}

// RuleMatching will be called by the engine when a rule is matched
func (y *YaraReader) RuleMatching(_ *yara.ScanContext, rule *yara.Rule) (bool, error) {
	y.Infected = true
	y.mrs = append(y.mrs, rule)
	return true, nil
}

// copy Helper for Next()
func (s *YaraReader) copy(buf []byte) {
	copy(buf, s.buf[:s.length])
}

// first Helper for First()
func (s *YaraReader) first(buf []byte) {
	copy(buf, s.firstBlockData[:s.firstBlock.Size])
}

// WithFilenameTip Will tip the Decoder on possible archive types
func WithFilenameTip(filename string) YaraReaderOpt {
	return func(reader *YaraReader) {
		reader.filename = filename
		reader.yaraVars["filename"] = filename
	}
}

// WithMaxLevel Will prevent the Reader to inspect archives under and given level
func WithMaxLevel(level int) YaraReaderOpt {
	return func(reader *YaraReader) {
		reader.level = level
	}
}

// WithBlockSize Sets the default buffer and block size for in-memory scanning
func WithBlockSize(size int) YaraReaderOpt {
	return func(reader *YaraReader) {
		reader.maxBlockSize = size
	}
}

// WithYaraVar Sets an external variable to be passed to Yara rules
func WithYaraVar(varKey, varValue string) YaraReaderOpt {
	return func(reader *YaraReader) {
		reader.yaraVars[varKey] = varValue
	}
}
