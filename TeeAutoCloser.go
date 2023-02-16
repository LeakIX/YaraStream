package YaraStream

import "io"

func TeeReaderAutoClose(r io.Reader, w io.WriteCloser) io.Reader {
	return &teeReader{r, w, false}
}

type teeReader struct {
	r      io.Reader
	w      io.WriteCloser
	closed bool
}

func (t *teeReader) Read(p []byte) (n int, err error) {
	n, err = t.r.Read(p)
	if err == io.EOF && !t.closed {
		t.closed = true
		return 0, t.w.Close()
	}
	if n > 0 {
		if n, err := t.w.Write(p[:n]); err != nil {
			return n, err
		}
	}
	return
}
