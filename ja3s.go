// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package ja3

import (
	"crypto/md5"
	"encoding/hex"
)

// JA3S stores the parsed fields from the Server Hello. To access the values use the respective getter methods.
type JA3S struct {
	version        uint16
	cipherSuite    uint16
	extensions     []uint16
	ja3SByteString []byte
	ja3SHash       string
}

// ComputeJA3FromSegment parses the segment and returns the populated JA3S object or the encountered parsing error.
func ComputeJA3SFromSegment(payload []byte) (*JA3S, error) {
	ja3s := JA3S{}
	err := ja3s.parseSegment(payload)
	return &ja3s, err
}

// GetJA3ByteString returns the JA3S string as a byte slice for more efficient handling. This function uses caching, so
// repeated calls to this function on the same JA3S object will not trigger any new calculations.
func (j *JA3S) GetJA3SByteString() []byte {
	if j.ja3SByteString == nil {
		j.marshalJA3S()
	}
	return j.ja3SByteString
}

// GetJA3String returns the JA3S string as a string. This function uses caching, so repeated calls to this function on
// the same JA3S object will not trigger any new calculations.
func (j *JA3S) GetJA3SString() string {
	return string(j.GetJA3SByteString())
}

// GetJA3Hash returns the MD5 Digest of the JA3S string in hexadecimal representation. This function uses caching, so
// repeated calls to this function on the same JA3S object will not trigger any new calculations.
func (j *JA3S) GetJA3Hash() string {
	if j.ja3SHash == "" {
		h := md5.Sum(j.GetJA3SByteString())
		j.ja3SHash = hex.EncodeToString(h[:])
	}
	return j.ja3SHash
}
