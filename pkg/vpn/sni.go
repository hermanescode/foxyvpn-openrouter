package vpn

import (
	"encoding/binary"
)

// ExtractSNI parses the Server Name Indication (SNI) from a TLS ClientHello packet.
// Returns the domain name if found, or empty string if not found or not a valid ClientHello.
func ExtractSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// Must be TLS Handshake record (0x16)
	if data[0] != 0x16 {
		return ""
	}

	// Total record length
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		// incomplete, but try with what we have
		if len(data) < 42 {
			return ""
		}
	}

	pos := 5
	// Check Handshake Type: ClientHello (0x01)
	if pos >= len(data) || data[pos] != 0x01 {
		return ""
	}
	pos++

	// Handshake length (3 bytes)
	if pos+3 > len(data) {
		return ""
	}
	pos += 3

	// Client version (2 bytes)
	if pos+2 > len(data) {
		return ""
	}
	pos += 2

	// Client random (32 bytes)
	if pos+32 > len(data) {
		return ""
	}
	pos += 32

	// Session ID length (1 byte) + Session ID
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos > len(data) {
		return ""
	}

	// Cipher Suites length (2 bytes) + Cipher Suites
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos > len(data) {
		return ""
	}

	// Compression methods length (1 byte) + Compression methods
	if pos >= len(data) {
		return ""
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos > len(data) {
		return ""
	}

	// Extensions length (2 bytes)
	if pos+2 > len(data) {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+extensionsLen > len(data) {
		extensionsLen = len(data) - pos
	}

	extensionsEnd := pos + extensionsLen
	for pos+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extLen > extensionsEnd {
			break
		}

		// extType 0 is server_name (SNI)
		if extType == 0 {
			sniPos := pos
			if sniPos+2 > pos+extLen {
				break
			}
			serverNameListLen := int(binary.BigEndian.Uint16(data[sniPos : sniPos+2]))
			sniPos += 2
			if sniPos+serverNameListLen > pos+extLen {
				break
			}

			for sniPos+3 <= pos+extLen {
				nameType := data[sniPos]
				nameLen := int(binary.BigEndian.Uint16(data[sniPos+1 : sniPos+3]))
				sniPos += 3
				if nameType == 0 { // host_name
					if sniPos+nameLen <= pos+extLen {
						return string(data[sniPos : sniPos+nameLen])
					}
				}
				sniPos += nameLen
			}
		}

		pos += extLen
	}

	return ""
}
