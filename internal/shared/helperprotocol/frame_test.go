package helperprotocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTripAndLengthValidation(t *testing.T) {
	payload := []byte(`{"message_type":"test"}`)
	var framed bytes.Buffer
	if err := WriteFrame(&framed, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}

	var oversized bytes.Buffer
	if err := binary.Write(&oversized, binary.BigEndian, uint32(MaxFrameBytes+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(&oversized); err == nil {
		t.Fatal("oversized frame accepted")
	}

	var truncated bytes.Buffer
	if err := binary.Write(&truncated, binary.BigEndian, uint32(8)); err != nil {
		t.Fatal(err)
	}
	truncated.WriteString("short")
	if _, err := ReadFrame(&truncated); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

type shortWriter struct {
	writes int
}

func (w *shortWriter) Write(payload []byte) (int, error) {
	w.writes++
	if w.writes == 1 {
		return len(payload), nil
	}
	if len(payload) == 0 {
		return 0, nil
	}
	return len(payload) - 1, nil
}

func TestWriteFrameRejectsShortPayloadWrite(t *testing.T) {
	err := WriteFrame(&shortWriter{}, []byte(`{"ok":true}`))
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteFrame error = %v, want io.ErrShortWrite", err)
	}
}
