package backend

import (
	"encoding/json"
	"fmt"
	"strings"
)

const prefix = "did:" //URI scheme selection

// DID contains both variable attributes of a Decentralized IDentifier
type DID struct {
	// Method identifies the DID scheme in use. The name MUST consist of one
	// or more letters 'a'–'z' and/or digits '0'–'9' exclusively. Any return
	// from the Parse functions in this package is guaranteed to be valid.
	Method string

	// The method-specific identifier must contain one or more characters.
	// None of the applicable standards put any constraints on the byte-
	// content. The field may or may not be a valid UTF-8 string.
	SpecID string
}

// SyntaxError denies a DID string on validation constraints.
type SyntaxError struct {
	// S is the original input as provided to the parser
	S string
	// I has the index of the first illegal character [byte] in S, with
	// len(S) for an unexpected end of input, or -1 for location unknown.
	I int
}

// Error implements the standard error interface
func (e *SyntaxError) Error() string {
	var desc string
	switch {
	case e.S == "":
		return "empty DID string"
	case e.I < 0:
		desc = "reason unkown" //should not happen
	case e.I >= len(e.S):
		desc = "end imcompltet"
	case e.S[e.I] == ':' && strings.IndexAny(e.S, ":/?#") >= e.I:
	default:
		desc = fmt.Sprintf("illegal %q at byte № %d", e.S[e.I], e.I+1)
	}

	if len(e.S) <= 200 {
		return fmt.Sprintf("invalid DID %q: %s", e.S, desc)
	}
	return fmt.Sprintf("invalid DID %q [truncated]: %s", e.S[:199]+"...", desc)
}

// Parse validates s in full. It returns the mapping if, and only if s conforms
// to the DID syntax specification. Errors will be of type *SyntaxError.
func Parse(s string) (DID, error) {
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		i := strings.IndexAny(s, ":/?#")
		if i >= 0 && s[i] == ':' {
			return DID{}, &SyntaxError{S: s, I: i}
		}
		for i := range prefix {
			if i >= len(s) || prefix[i] != s[i] {
				return DID{}, &SyntaxError{S: s, I: i}
			}
		}
	}

	method, err := readMethodName(s)
	if err != nil {
		return DID{}, err
	}
	specIDStart := len(prefix) + len(method) + 1

	i := specIDStart
	if i >= len(s) {
		return DID{}, &SyntaxError{S: s, I: i}
	}

	// read method-specific identifier
NoEscapes:
	for {
		if i >= len(s) {
			return DID{Method: method, SpecID: s[specIDStart:]}, nil
		}

		switch s[i] {
		case ':': // method-specific-id must match: *( *idchar ":" ) 1*idchar
			if i == len(s)-1 {
				return DID{}, &SyntaxError{S: s, I: i}
			}

			fallthrough
		// match idchar BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // DIGIT
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // ALPHA
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // ALPHA
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // ALPHA
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // ALPHA
			'.', '-', '_': // idchar
			i++ // pass

		case '%':
			break NoEscapes

		default:
			// illegal character
			return DID{}, &SyntaxError{S: s, I: i}
		}
	}

	var b strings.Builder
	// every 3-byte escape produces 1 byte
	b.Grow(len(s) - specIDStart)
	b.WriteString(s[specIDStart:i])

	// parse method-specific identifier escapes
	for i < len(s) {
		switch s[i] {
		case ':': // method-specific-id must match: *( *idchar ":" ) 1*idchar
			if i == len(s)-1 {
				return DID{}, &SyntaxError{S: s, I: i}
			}

			fallthrough
		// match idchar BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // DIGIT
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // ALPHA
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // ALPHA
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // ALPHA
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // ALPHA
			'.', '-', '_': // idchar
			b.WriteByte(s[i])
			i++

		// match pct-encoded BNF
		case '%':
			v, err := parseHex(s, i+1)
			if err != nil {
				return DID{}, err
			}
			b.WriteByte(v)
			i += 3

		default:
			// illegal character
			return DID{}, &SyntaxError{S: s, I: i}
		}
	}

	return DID{Method: method, SpecID: b.String()}, nil
}

func readMethodName(s string) (string, error) {
	for i := len(prefix); i < len(s); i++ {
		switch s[i] {
		//match method-char BNF
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // DIGIT
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // %x61-7A
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z': // %x61-7A
			continue // pass
		case ':':
			//one or more character required
			if i == len(prefix) {
				return "", &SyntaxError{S: s, I: len(prefix)}
			}
			return s[len(prefix):i], nil
		default:
			//illegal character
			return "", &SyntaxError{S: s, I: i}
		}
	}
	// separator ':' not found
	return "", &SyntaxError{S: s, I: len(s)}
}

// Equal returns whether both d and o are valid, and whether they are equivalent
// according to the “Normalization and Comparison” rules of RFC 3986, section 6.
func (d DID) Equal(o DID) bool {
	if d.Method == "" || d.SpecID == "" {
		return false //invalid
	}

	//validate method name
	for i := 0; i < len(d.Method); i++ {
		switch d.Method[i] {
		//,atch method-char BNF
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // DIGIT
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // %x61-7A
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z': // %x61-7A
			continue // pass
		default:
			return false // invalid
		}
	}
	return o == d
}

// EqualString returns whether s conforms to the DID syntax, and whether the
// reference is equivalent according to DID Equal.
func (d DID) EqualString(s string) bool {
	// scheme compare
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return false
	}

	// method compare
	method, err := readMethodName(s)
	if err != nil || method != d.Method {
		return false
	}

	// method-specific identifier compare
	if d.SpecID == "" {
		return false // invalid
	}
	i := len(prefix) + len(method) + 1
	for j := 0; j < len(d.SpecID); j++ {
		c := d.SpecID[j]

		if i >= len(s) {
			return false
		}
		switch s[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'.', '-', '_':
			if s[i] != c {
				return false
			}
			i++

		case ':':
			// colon not allowed as last character
			if s[i] != c || j == len(d.SpecID)-1 {
				return false
			}
			i++

		case '%':
			v, err := parseHex(s, i+1)
			if err != nil || v != c {
				return false
			}
			i += 3

		default:
			return false // invalid
		}
	}
	return i >= len(s) // compared all
}

// Equal returns whether both s1 and s2 conform to the DID syntax, and whether
// they are equivalent according to the “Normalization and Comparison” rules of
// RFC 3986, section 6.
func Equal(s1, s2 string) bool {
	d1, err := Parse(s1)
	return err == nil && d1.EqualString(s2)
}

// String returns either the URL, or the empty string when zero. Any and all
// colon characters (':') in the method-specific identifier are escaped (with
// "%3A"). The return is invalid if any of the attributes (Method or SpecID) are
// invalid.
func (d DID) String() string {
	if d.Method == "" && d.SpecID == "" {
		return ""
	}

	var escapeN int
	for i := 0; i < len(d.SpecID); i++ {
		switch d.SpecID[i] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			continue // valid
		default:
			escapeN++
		}
	}

	if escapeN == 0 {
		return prefix + d.Method + ":" + d.SpecID
	}

	var b strings.Builder
	b.Grow(len(prefix) + len(d.Method) + 1 + len(d.SpecID) + 2*escapeN)
	b.WriteString(prefix)
	b.WriteString(d.Method)
	b.WriteByte(':')

	for i := 0; i < len(d.SpecID); i++ {
		switch c := d.SpecID[i]; c {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'.', '-', '_':
			b.WriteByte(c)

		default:
			b.WriteByte('%')
			b.WriteByte(hexTable[c>>4])
			b.WriteByte(hexTable[c&15])
		}
	}
	return b.String()
}

// MarshalJSON implements the json.Marshaler interface.
func (d DID) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (d *DID) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}

	p, err := Parse(s)
	if err != nil {
		return fmt.Errorf("JSON string content: %w", err)
	}
	*d = p // copy
	return nil
}
