package structs

import (
	"bufio"
	"fmt"
	"io"
	"maps"
	"slices"

	"github.com/Pro7ech/lattigo/utils/buffer"
	"golang.org/x/exp/constraints"
)

// Map is a struct storing a map of any value indexed by unsigned integers.
// The size of the map is limited to 2^32.
type Map[K constraints.Integer, T any] map[K]*T

// Clone creates a copy of the object.
func (m Map[K, T]) Clone() *Map[K, T] {

	if c, isCopiable := any(new(T)).(Cloner[T]); !isCopiable {
		panic(fmt.Errorf("vector component of type %T does not comply to %T", new(T), c))
	}

	var mcpy = make(Map[K, T])

	for key := range m {
		mcpy[key] = any(m[key]).(Cloner[T]).Clone()
	}

	return &mcpy
}

// WriteTo writes the object on an io.Writer. It implements the io.WriterTo
// interface, and will write exactly object.BinarySize() bytes on w.
//
// Unless w implements the buffer.Writer interface (see lattigo/utils/buffer/writer.go),
// it will be wrapped into a bufio.Writer. Since this requires allocations, it
// is preferable to pass a buffer.Writer directly:
//
//   - When writing multiple times to a io.Writer, it is preferable to first wrap the
//     io.Writer in a pre-allocated bufio.Writer.
//   - When writing to a pre-allocated var b []byte, it is preferable to pass
//     buffer.NewBuffer(b) as w (see lattigo/utils/buffer/buffer.go).
func (m *Map[K, T]) WriteTo(w io.Writer) (n int64, err error) {

	if w, isWritable := any(new(T)).(io.WriterTo); !isWritable {
		return 0, fmt.Errorf("vector component of type %T does not comply to %T", new(T), w)
	}

	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteUint32(w, uint32(len(*m))); err != nil {
			return n + inc, err
		}
		n += inc

		keys := slices.Sorted(maps.Keys(*m))

		for _, key := range keys {

			if inc, err = buffer.WriteUint64(w, uint64(key)); err != nil {
				return n + inc, err
			}
			n += inc

			val := (*m)[key]
			if inc, err = any(val).(io.WriterTo).WriteTo(w); err != nil {
				return n + inc, err
			}

			n += inc
		}

		return

	default:
		return m.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads on the object from an io.Writer. It implements the
// io.ReaderFrom interface.
//
// Unless r implements the buffer.Reader interface (see lattigo/utils/buffer/reader.go),
// it will be wrapped into a bufio.Reader. Since this requires allocation, it
// is preferable to pass a buffer.Reader directly:
//
//   - When reading multiple values from a io.Reader, it is preferable to first
//     first wrap io.Reader in a pre-allocated bufio.Reader.
//   - When reading from a var b []byte, it is preferable to pass a buffer.NewBuffer(b)
//     as w (see lattigo/utils/buffer/buffer.go).
func (m *Map[K, T]) ReadFrom(r io.Reader) (n int64, err error) {

	if r, isReadable := any(new(T)).(io.ReaderFrom); !isReadable {
		return 0, fmt.Errorf("vector component of type %T does not comply to %T", new(T), r)
	}

	switch r := r.(type) {
	case buffer.Reader:

		var inc int64
		var size uint32
		if inc, err = buffer.ReadUint32(r, &size); err != nil {
			return n + inc, err
		}
		n += inc

		if (*m) == nil {
			*m = make(Map[K, T], size)
		}

		for i := 0; i < int(size); i++ {

			var key uint64
			if inc, err = buffer.ReadUint64(r, &key); err != nil {
				return n + inc, err
			}
			n += inc

			var val = new(T)
			if inc, err = any(val).(io.ReaderFrom).ReadFrom(r); err != nil {
				return n + inc, err
			}
			(*m)[K(key)] = val

			n += inc
		}

		return

	default:
		return m.ReadFrom(bufio.NewReader(r))
	}
}

// BinarySize returns the serialized size of the object in bytes.
func (m Map[K, T]) BinarySize() (size int) {

	if s, isSizable := any(new(T)).(BinarySizer); !isSizable {
		panic(fmt.Errorf("vector component of type %T does not comply to %T", new(T), s))
	}

	size = 4 // #Ct

	for _, v := range m {
		size += 8
		size += any(v).(BinarySizer).BinarySize()
	}

	return
}

// MarshalBinary encodes the object into a binary form on a newly allocated slice of bytes.
func (m *Map[K, T]) MarshalBinary() (p []byte, err error) {
	buf := buffer.NewBufferSize(m.BinarySize())
	_, err = m.WriteTo(buf)
	return buf.Bytes(), err
}

// UnmarshalBinary decodes a slice of bytes generated by
// MarshalBinary or WriteTo on the object.
func (m *Map[K, T]) UnmarshalBinary(p []byte) (err error) {
	_, err = m.ReadFrom(buffer.NewBuffer(p))
	return
}
