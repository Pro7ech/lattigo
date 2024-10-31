package hefloat

import (
	"bufio"
	"encoding/json"
	"io"
	"math"

	"github.com/Pro7ech/lattigo/ring"
	"github.com/Pro7ech/lattigo/rlwe"
	"github.com/Pro7ech/lattigo/utils/buffer"
	"github.com/Pro7ech/lattigo/utils/structs"
)

// ParametersLiteral is a literal representation of CKKS parameters.  It has public
// fields and is used to express unchecked user-defined parameters literally into
// Go programs. The NewParametersFromLiteral function is used to generate the actual
// checked parameters from the literal representation.
//
// Users must set the polynomial degree (in log_2, LogN) and the coefficient modulus, by either setting
// the Q and P fields to the desired moduli chain, or by setting the LogQ and LogP fields to
// the desired moduli sizes (in log_2). Users must also specify a default initial scale for the plaintexts.
//
// Optionally, users may specify the error variance (Sigma), the secrets' density (H), the ring
// type (RingType) and the number of slots (in log_2, LogSlots). If left unset, standard default values for
// these field are substituted at parameter creation (see NewParametersFromLiteral).
type ParametersLiteral struct {
	LogN            int
	LogNthRoot      int                         `json:",omitempty"`
	Q               structs.Vector[uint64]      `json:",omitempty"`
	P               structs.Vector[uint64]      `json:",omitempty"`
	LogQ            structs.Vector[int]         `json:",omitempty"`
	LogP            structs.Vector[int]         `json:",omitempty"`
	Xe              ring.DistributionParameters `json:",omitempty"`
	Xs              ring.DistributionParameters `json:",omitempty"`
	RingType        ring.Type                   `json:",omitempty"`
	LogDefaultScale int                         `json:",omitempty"`
}

// GetRLWEParametersLiteral returns the rlwe.ParametersLiteral from the target ckks.ParameterLiteral.
func (p ParametersLiteral) GetRLWEParametersLiteral() rlwe.ParametersLiteral {
	return rlwe.ParametersLiteral{
		LogN:         p.LogN,
		LogNthRoot:   p.LogNthRoot,
		Q:            p.Q,
		P:            p.P,
		LogQ:         p.LogQ,
		LogP:         p.LogP,
		Xe:           p.Xe,
		Xs:           p.Xs,
		RingType:     p.RingType,
		NTTFlag:      true,
		DefaultScale: rlwe.NewScale(math.Exp2(float64(p.LogDefaultScale))),
	}
}

func (p ParametersLiteral) BinarySize() (size int) {
	size++ // LogN
	size++ // LogNthRoot
	size += p.Q.BinarySize()
	size += p.P.BinarySize()
	size += p.LogQ.BinarySize()
	size += p.LogP.BinarySize()
	size += p.Xe.BinarySize()
	size += p.Xs.BinarySize()
	size++ // RingType
	size++ // LogDefaultScale
	return
}

func (p ParametersLiteral) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:

		var inc int64

		if inc, err = buffer.WriteAsUint8(w, p.LogN); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.LogNthRoot); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Q.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.P.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogQ.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogP.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Xe.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Xs.WriteTo(w); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.RingType); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.WriteAsUint8(w, p.LogDefaultScale); err != nil {
			return n + inc, err
		}

		n += inc

		return n, w.Flush()
	default:
		return p.WriteTo(bufio.NewWriter(w))
	}
}

func (p *ParametersLiteral) ReadFrom(r io.Reader) (n int64, err error) {
	switch r := r.(type) {
	case buffer.Reader:

		var inc int64

		if inc, err = buffer.ReadAsUint8(r, &p.LogN); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.LogNthRoot); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.Q.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.P.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogQ.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = p.LogP.ReadFrom(r); err != nil {
			return n + inc, err
		}

		n += inc

		if p.Xe, inc, err = ring.DistributionParametersFromReader(r); err != nil {
			return n + inc, err
		}

		n += inc

		if p.Xs, inc, err = ring.DistributionParametersFromReader(r); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.RingType); err != nil {
			return n + inc, err
		}

		n += inc

		if inc, err = buffer.ReadAsUint8(r, &p.LogDefaultScale); err != nil {
			return n + inc, err
		}

		n += inc

		return
	default:
		return p.ReadFrom(bufio.NewReader(r))
	}
}

func (p ParametersLiteral) MarshalBinary() (data []byte, err error) {
	buf := buffer.NewBufferSize(p.BinarySize())
	_, err = p.WriteTo(buf)
	return buf.Bytes(), err
}

func (p *ParametersLiteral) UnmarshalBinary(data []byte) (err error) {
	_, err = p.ReadFrom(buffer.NewBuffer(data))
	return
}

func (p *ParametersLiteral) UnmarshalJSON(b []byte) (err error) {
	var pl struct {
		LogN            int
		LogNthRoot      int
		Q               []uint64
		P               []uint64
		LogQ            []int
		LogP            []int
		Pow2Base        int
		Xe              map[string]interface{}
		Xs              map[string]interface{}
		RingType        ring.Type
		LogDefaultScale int
	}

	err = json.Unmarshal(b, &pl)
	if err != nil {
		return err
	}

	p.LogN = pl.LogN
	p.LogNthRoot = pl.LogNthRoot
	p.Q, p.P, p.LogQ, p.LogP = pl.Q, pl.P, pl.LogQ, pl.LogP
	if pl.Xs != nil {
		p.Xs, err = ring.DistributionParametersFromMap(pl.Xs)
		if err != nil {
			return err
		}
	}
	if pl.Xe != nil {
		p.Xe, err = ring.DistributionParametersFromMap(pl.Xe)
		if err != nil {
			return err
		}
	}
	p.RingType = pl.RingType
	p.LogDefaultScale = pl.LogDefaultScale

	return err
}
