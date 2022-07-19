// Copyright (c) 2018, Open Systems AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package ja3

import "strconv"

// parseSegment to populate the corresponding JA3S object or return an error
func (j *JA3S) parseSegment(segment []byte) error {

	// Check if we can decode the next fields
	if len(segment) < recordLayerHeaderLen {
		return &ParseError{LengthErr, 1}
	}

	// Check if we have "Content Type: Handshake (22)"
	contType := uint8(segment[0])
	if contType != contentType {
		return &ParseError{errType: ContentTypeErr}
	}

	// Check if TLS record layer version is supported
	tlsRecordVersion := uint16(segment[1])<<8 | uint16(segment[2])
	if tlsRecordVersion&tlsVersionBitmask != 0x0300 && tlsRecordVersion != tls13 {
		return &ParseError{VersionErr, 1}
	}

	// Handshake messege
	hs := segment[recordLayerHeaderLen:]

	err := j.parseHandshake(hs)

	return err
}

// parseHandshake body
func (j *JA3S) parseHandshake(hs []byte) error {

	// Check if we can decode the next fields
	if len(hs) < handshakeHeaderLen+randomDataLen+sessionIDHeaderLen {
		return &ParseError{LengthErr, 3}
	}

	// Check if we have "Handshake Type: Server Hello (1)"
	handshType := uint8(hs[0])
	if handshType != serverHelloHandshakeType {
		return &ParseError{errType: HandshakeTypeErr}
	}

	// Check if actual length of handshake matches (this is a great exclusion criterion for false positives,
	// as these fields have to match the actual length of the rest of the segment)
	handshakeLen := uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3])
	if len(hs[4:]) < int(handshakeLen) {
		return &ParseError{LengthErr, 4}
	}

	hs = hs[:handshakeLen+4]

	// Check if Server Hello version is supported
	if len(hs) < handshakeHeaderLen {
		return &ParseError{LengthErr, 500}
	}
	tlsVersion := uint16(hs[4])<<8 | uint16(hs[5])
	if tlsVersion&tlsVersionBitmask != 0x0300 && tlsVersion != tls13 {
		return &ParseError{VersionErr, 2}
	}
	j.version = tlsVersion

	// Check if we can decode the next fields
	sessionIDLen := uint8(hs[38])
	if len(hs) < handshakeHeaderLen+randomDataLen+sessionIDHeaderLen+int(sessionIDLen) {
		return &ParseError{LengthErr, 5}
	}

	// Cipher Suite
	cs := hs[handshakeHeaderLen+randomDataLen+sessionIDHeaderLen+int(sessionIDLen):]

	// Check if we can decode the next fields
	if len(cs) < cipherSuiteHeaderLen {
		return &ParseError{LengthErr, 6}
	}

	j.cipherSuite = uint16(cs[0])<<8 | uint16(cs[1])

	// Check if we can decode the next fields
	// compressMethodLen := uint16(cs[cipherSuiteHeaderLen])
	if len(cs) < cipherSuiteHeaderLen+compressMethodHeaderLen {
		return &ParseError{LengthErr, 8}
	}

	// Extensions
	exs := cs[cipherSuiteHeaderLen+compressMethodHeaderLen:]

	err := j.parseExtensions(exs)

	return err
}

// parseExtensions of the handshake
func (j *JA3S) parseExtensions(exs []byte) error {

	// Check for no extensions, this fields header is nonexistent if no body is used
	if len(exs) == 0 {
		return nil
	}

	// Check if we can decode the next fields
	if len(exs) < extensionsHeaderLen {
		return &ParseError{LengthErr, 9}
	}

	exsLen := uint16(exs[0])<<8 | uint16(exs[1])
	exs = exs[extensionsHeaderLen:]

	// Check if we can decode the next fields
	if len(exs) < int(exsLen) {
		return &ParseError{LengthErr, 10}
	}

	var extensions []uint16
	for len(exs) > 0 {

		// Check if we can decode the next fields
		if len(exs) < extensionHeaderLen {
			return &ParseError{LengthErr, 11}
		}

		exType := uint16(exs[0])<<8 | uint16(exs[1])
		exLen := uint16(exs[2])<<8 | uint16(exs[3])
		// Ignore any GREASE extensions
		if exType&greaseBitmask != 0x0A0A {
			extensions = append(extensions, exType)
		}

		// Check if we can decode the next fields
		if len(exs) < extensionHeaderLen+int(exLen) {
			break
		}

		exs = exs[4+exLen:]
	}
	j.extensions = extensions
	return nil
}

// marshalJA3S into a byte string
func (j *JA3S) marshalJA3S() {

	// An uint16 can contain numbers with up to 5 digits and an uint8 can contain numbers with up to 3 digits, but we
	// also need a byte for each separating character, except at the end.
	byteStringLen := 6*(1+cipherSuiteHeaderLen+len(j.extensions)) - 1
	byteString := make([]byte, 0, byteStringLen)

	// Version
	byteString = strconv.AppendUint(byteString, uint64(j.version), 10)
	byteString = append(byteString, commaByte)

	// Accepted Cipher Suite
	byteString = strconv.AppendUint(byteString, uint64(j.cipherSuite), 10)
	byteString = append(byteString, commaByte)

	// Extensions
	if len(j.extensions) != 0 {
		for _, val := range j.extensions {
			byteString = strconv.AppendUint(byteString, uint64(val), 10)
			byteString = append(byteString, dashByte)
		}
		// Remove last dash
		byteString = byteString[:len(byteString)-1]
	}

	j.ja3SByteString = byteString
}
