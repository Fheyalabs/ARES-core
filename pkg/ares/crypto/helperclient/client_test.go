package helperclient

import (
	"testing"
)

func TestSharpenSignDegree3_Shape(t *testing.T) {
	p := SharpenSignDegree3()
	if len(p.Coefficients) != 4 {
		t.Errorf("degree-3 should have 4 coefficients, got %d", len(p.Coefficients))
	}
	// Odd polynomial: even-indexed coefficients are zero.
	for i := 0; i < len(p.Coefficients); i += 2 {
		if p.Coefficients[i] != 0 {
			t.Errorf("coeff[%d] = %v, want 0 (odd polynomial)", i, p.Coefficients[i])
		}
	}
	if p.LowerBound != -1.0 || p.UpperBound != 1.0 {
		t.Errorf("domain = [%v,%v], want [-1,1]", p.LowerBound, p.UpperBound)
	}
}

func TestSharpenSignDegree9_OddOnly(t *testing.T) {
	p := SharpenSignDegree9()
	if len(p.Coefficients) != 10 {
		t.Errorf("degree-9 should have 10 coefficients, got %d", len(p.Coefficients))
	}
	for i := 0; i < len(p.Coefficients); i += 2 {
		if p.Coefficients[i] != 0 {
			t.Errorf("coeff[%d] = %v, want 0 (odd polynomial)", i, p.Coefficients[i])
		}
	}
}

func TestSharpenChebyshev_NilCoeffs(t *testing.T) {
	p := SharpenChebyshev(-2.0, 2.0, 9)
	if p.Coefficients != nil {
		t.Errorf("Chebyshev sentinel should leave Coefficients nil; got %v", p.Coefficients)
	}
	if p.LowerBound != -2.0 || p.UpperBound != 2.0 {
		t.Errorf("domain = [%v,%v], want [-2,2]", p.LowerBound, p.UpperBound)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	original := []byte{1, 2, 3, 0xff, 0x00, 0x42}
	encoded := encodeB64(original)
	decoded, err := decodeB64(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(original) {
		t.Errorf("roundtrip mismatch: %v vs %v", original, decoded)
	}
}

func TestDecodeB64_Empty(t *testing.T) {
	b, err := decodeB64("")
	if err != nil {
		t.Errorf("empty decode should be nil-no-error, got %v", err)
	}
	if b != nil {
		t.Errorf("empty decode should produce nil bytes, got %v", b)
	}
}

func TestDecodeB64_Invalid(t *testing.T) {
	_, err := decodeB64("not-valid-base64!@#")
	if err == nil {
		t.Errorf("expected error decoding invalid base64")
	}
}

func TestHelperError_Format(t *testing.T) {
	e := &HelperError{Op: "argmax", Msg: "depth too low"}
	want := `helper op "argmax": depth too low`
	if e.Error() != want {
		t.Errorf("Error() = %q, want %q", e.Error(), want)
	}
}
