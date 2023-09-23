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
}

func (s *YaraScanner) ScanReader(reader io.Reader, opts ...func(writer *YaraReader)) ([]*yara.Rule, error) {
	bufferedReader := bufio.NewReaderSize(reader, 16*1024)
	testReader := &YaraReader{
		r:     bufferedReader,
		level: 10,
	}
	for _, option := range opts {
		option(testReader)
	}
	dec, err := decoder.GetDecoder("", testReader.r)
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
				partResults, _ := s.ScanReader(dec, ReaderWithFilenameTip(entry.Filename), ReaderWithCurrentLevel(testReader.level-1))
				testReader.mrs = append(testReader.mrs, partResults...)
			}
		}
	}
	testReader.scanner, _ = yara.NewScanner(s.rules)
	defer testReader.scanner.Destroy()
	testReader.scanner.SetFlags(yara.ScanFlagsProcessMemory)
	testReader.scanner.SetCallback(testReader)
	testReader.buf = make([]byte, 16*1024)
	testReader.firstBlockData = make([]byte, 16*1024)
	err = testReader.scanner.ScanMemBlocks(testReader)

	return testReader.mrs, err
}

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

func (y *YaraReader) RuleMatching(_ *yara.ScanContext, rule *yara.Rule) (bool, error) {
	y.Infected = true
	y.mrs = append(y.mrs, rule)
	return true, nil
}

func (s *YaraReader) copy(buf []byte) {
	copy(buf, s.buf[:s.length])
}
func (s *YaraReader) first(buf []byte) {
	copy(buf, s.firstBlockData[:s.firstBlock.Size])
	//log.Println(s.filename, s.firstBlock.Base, s.firstBlock.Size, string(buf))

}

func ReaderWithFilenameTip(filename string) func(writer *YaraReader) {
	return func(writer *YaraReader) {
		writer.filename = filename
	}
}

func ReaderWithCurrentLevel(level int) func(writer *YaraReader) {
	return func(writer *YaraReader) {
		writer.level = level
	}
}
