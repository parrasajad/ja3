package ja3

import (
	"crypto/md5"
	"encoding/hex"
)

// JA3 stores the parsed fields from the Client Hello. To access the values use the respective getter methods.
type JA3 struct {
	version         uint16
	cipherSuites    []uint16
	extensions      []uint16
	ellipticCurves  []uint16
	ellipticCurvePF []uint8
	sni             []byte
	ja3ByteString   []byte
	ja3String       string
	ja3Hash         string
}

// ComputeJA3FromSegment parses the segment and returns the populated JA3 object or the encountered parsing error.
func ComputeJA3FromSegment(payload []byte) (*JA3, error) {
	ja3 := JA3{}
	err := ja3.parseSegment(payload)
	return &ja3, err
}

// GetJA3ByteString returns the JA3 string as a byte slice for more efficient handling. This function uses caching, so
// repeated calls to this function on the same JA3 object will not trigger any new calculations.
func (j *JA3) GetJA3ByteString() []byte {
	if j.ja3ByteString == nil {
		j.marshalJA3()
	}
	return j.ja3ByteString
}

// GetJA3String returns the JA3 string as a string. This function uses caching, so repeated calls to this function on
// the same JA3 object will not trigger any new calculations.
func (j *JA3) GetJA3String() string {
	if j.ja3String == "" {
		j.ja3String = string(j.GetJA3ByteString())
	}
	return j.ja3String
}

// GetJA3Hash returns the MD5 Digest of the JA3 string in hexadecimal representation. This function uses caching, so
// repeated calls to this function on the same JA3 object will not trigger any new calculations.
func (j *JA3) GetJA3Hash() string {
	if j.ja3Hash == "" {
		h := md5.Sum(j.GetJA3ByteString())
		j.ja3Hash = hex.EncodeToString(h[:])
	}
	return j.ja3Hash
}

// GetSNI returns the set SNI in the Client Hello or an empty string if no SNI extension is found. This function uses
// caching, so repeated calls to this function on the same JA3 object will not trigger any new calculations.
func (j *JA3) GetSNI() string {
	return string(j.sni)
}