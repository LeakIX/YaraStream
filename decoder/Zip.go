package decoder

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/krolaw/zipstream"
	"strings"
)

func init() {
	Registrations = append(Registrations, Registration{
		MatchFileHeader: func(_ string, headerBytes []byte) bool {
			return bytes.HasPrefix(headerBytes, []byte("PK\x03\x04"))
		},
		GetDecoder: GetZipDecoder,
	})
}

type ZipDecoder struct {
	reader *zipstream.Reader
}

func GetZipDecoder(_ string, reader *bufio.Reader) (Decoder, error) {
	return &ZipDecoder{
		reader: zipstream.NewReader(reader),
	}, nil
}

func (d *ZipDecoder) Read(p []byte) (_ int, err error) {
	// Set the default error return value
	err = errors.New("error reading zip file")
	defer func() {
		// Recover on read issues
		_ = recover()
	}()
	return d.reader.Read(p)
}

func (d *ZipDecoder) Next() (_ *Entry, err error) {
	err = errors.New("error reading zip file")
	defer func() {
		// Recover on read issues
		_ = recover()
	}()
	header, err := d.reader.Next()
	if err != nil {
		return nil, err
	}
	fileEntry := &Entry{
		Filename: header.Name,
	}
	fileEntry.Type = "file"
	if strings.HasSuffix(fileEntry.Filename, "/") {
		fileEntry.Type = "dir"
	}
	return fileEntry, nil
}
