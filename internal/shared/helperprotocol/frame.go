package helperprotocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

func ReadFrame(reader io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("read protocol frame length: %w", err)
	}
	if size == 0 || size > MaxFrameBytes {
		return nil, fmt.Errorf("protocol frame length outside bounds")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("read protocol frame payload: %w", err)
	}
	return payload, nil
}

func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFrameBytes {
		return fmt.Errorf("protocol frame length outside bounds")
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(payload))); err != nil {
		return fmt.Errorf("write protocol frame length: %w", err)
	}
	written, err := writer.Write(payload)
	if err != nil {
		return fmt.Errorf("write protocol frame payload: %w", err)
	}
	if written != len(payload) {
		return fmt.Errorf("write protocol frame payload: %w", io.ErrShortWrite)
	}
	return nil
}
