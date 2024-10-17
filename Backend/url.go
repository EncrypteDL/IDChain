package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

// URL extends the syntax of a basic DID to incorporate other standard URI
// components such as path, query, and fragment in order to locate a particular
// resource—for example, a cryptographic public key inside a DID document, or a
// resource external to the DID document.
type URL struct {
	DID // may be zero when the URL IsRelative

	// The path is an optional URI component. Its raw (as in unmodified)
	// string may contain any number of percent-encoded octets. A relative
	// DID URL [IsRelative] may have a rootless path—not starting with a
	// slash ('/') character.
	RawPath string

	// The query is an optional URI component. Its raw (as in unmodified)
	// string may contain any number of percent-encoded octets. The first
	// first character should be a question mark ('?') if present.
	RawQuery string

	// The fragment is an optional URI component. Its raw (as in unmodified)
	// string may contain any number of percent-encoded octets. The first
	// first character should be a number sign ('#') if present.
	RawFragment string
}

func ParseURL(s string) (*URL, error) {
	if s == "" {
		return nil, &SyntaxError{}
	}
	var i int // s index
	var u URL // result

	// scheme match
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		i = strings.IndexAny(s, "/?#")
		if i < 0 {
			d, err := Parse(s)
			if err != nil {
				return nil, err
			}
			return &URL{DID: d}, nil
		}
		d, err := Parse(s[:i])
		if err != nil {
			err.(*SyntaxError).S = s
			return nil, err
		}
		u.DID = d
	} else {
		// Relative references need an additional check. “A path segment
		// that contains a colon character (e.g., "this:that") cannot be
		// used as the first segment of a relative-path reference, as it
		// would be mistaken for a scheme name.” — “URI: Generic Syntax”
		// RFC 3986, subsection 4.2
		for i := 0; i < len(s); i++ {
			switch s[i] {
			default:
				continue
			case ':':
				// got scheme in s[:i], and it is not "did"
				return nil, &SyntaxError{S: s, I: i}

			case '/', '?', '#':
				break
			}
			break
		}
	}
	offset := i

	// Read “Path” from “URI: Generic Syntax” RFC 3986, subsection 3.3.
	for {
		if i >= len(s) {
			u.RawPath = s[offset:]
			return &u, nil
		}

		switch s[i] {
		default:
			return nil, &SyntaxError{S: s, I: i}

		// match path BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar additions
			'/':
			i++
			continue

		// match pct-encoded BNF
		case '%':
			_, err := parseHex(s, i+1)
			if err != nil {
				return nil, err
			}
			i += 3
			continue

		case '?', '#':
			u.RawPath = s[offset:i]
			break
		}
		break
	}
	offset = i
	i++

	if s[offset] == '?' {
		// Read “Query” from “URI: Generic Syntax” RFC 3986, subsection 3.4.
		for {
			if i >= len(s) {
				u.RawQuery = s[offset:]
				return &u, nil
			}

			switch s[i] {
			default:
				return nil, &SyntaxError{S: s, I: i}

			// match path BNF excluding pct-encoded
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
				'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
				'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
				'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
				'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
				'-', '.', '_', '~', // unreserved
				'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
				':', '@', // pchar
				'/', '?': // query
				i++ // valid
				continue

			// match pct-encoded BNF
			case '%':
				_, err := parseHex(s, i+1)
				if err != nil {
					return nil, err
				}
				i += 3
				continue

			case '#':
				u.RawQuery = s[offset:i]
				offset = i
				break
			}
			break
		}
		offset = i
		i++
	}

	// Read “Fragment” from “URI: Generic Syntax” RFC 3986, subsection 3.5.
	for i < len(s) {
		switch s[i] {
		default:
			return nil, &SyntaxError{S: s, I: i}

		// match path BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/', '?': // fragment
			i++

		// match pct-encoded BNF
		case '%':
			_, err := parseHex(s, i+1)
			if err != nil {
				return nil, err
			}
			i += 3
		}
	}
	u.RawFragment = s[offset:]
	return &u, nil
}

// IsRelative returns whether u is a relative URI reference.
//
// “A relative DID URL is any URL value in a DID document that does not start
// with did:<method-name>:<method-specific-id>. More specifically, it is any URL
// value that does not start with the ABNF defined in 3.1 DID Syntax. The URL is
// expected to reference a resource in the same DID document.”
func (u *URL) IsRelative() bool { return u.Method == "" && u.SpecID == "" }

func (u *URL) Equal(o *URL) bool {
	// “Normalization should not remove delimiters when their associated
	// component is empty unless licensed to do so by the scheme
	// specification.”
	// — “URI: Generic Syntax” RFC 3986, subsection 6.2.3
	return !o.IsRelative() && o.DID.Equal(u.DID) &&
		escapedWithLeadEqual(o.RawFragment, u.RawFragment, '#') &&
		escapedWithLeadEqual(o.RawQuery, u.RawQuery, '?') &&
		pathEqual(o.RawPath, u.RawPath)
}

// EqualString returns whether whether s conforms to the DID URL syntax, and
// whether the reference is equivalent according to URL Equal.
func (u *URL) EqualString(s string) bool {
	o, err := ParseURL(s)
	return err == nil && u.Equal(o)
}

func URLEqual(s1, s2 string) bool {
	u1, err := ParseURL(s1)
	return err == nil && u1.EqualString(s2)
}

// EscapedWithLeadEqual returns whether a and b both have lead as the first
// character, if non-zero, and whether their remainders represent the same
// octet-sequence. Invalid encodings never compare equal.
func escapedWithLeadEqual(a, b string, lead byte) bool {
	switch {
	case a == b:
		return true // fast path
	case a == "", b == "":
		return false // one empty–other not
	case a[0] != lead, b[0] != lead:
		return false // invalid prefix (in raw field)
	}
	a = a[1:]
	b = b[1:]

	for {
		switch {
		case a == "":
			return b == ""
		case b == "":
			return false
		}

		var ac byte
		switch a[0] {
		// match query or fragment BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/', '?': // query or fragment
			ac = a[0]
			a = a[1:] // pass

		// match pct-encoded
		case '%':
			var err error
			ac, err = parseHex(a, 1)
			if err != nil {
				return false // invalid
			}
			a = a[3:] // pass

		default:
			return false // invalid
		}

		var bc byte
		switch b[0] {
		// match query or fragment BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/', '?': // query or fragment
			bc = b[0]
			b = b[1:] // pass

		// match pct-encoded
		case '%':
			var err error
			bc, err = parseHex(b, 1)
			if err != nil {
				return false // invalid
			}
			b = b[3:] // pass

		default:
			return false // invalid
		}

		if ac != bc {
			return false // payload mismatch
		}
	}
}

// PathEqual returns whether a and b represent the same path when normalized.
// Invalid encodings never compare equal.
func pathEqual(a, b string) bool {
	switch {
	case a == b:
		return true // fast path
	case a == "", b == "":
		return false // one empty–other not
	}
	// normalize without root (could be optimized with more code)
	a = path.Join("/", a)[1:]
	b = path.Join("/", b)[1:]

	for {
		switch {
		case a == "":
			return b == ""
		case b == "":
			return false
		}

		var ac byte
		var aEscSep bool
		switch a[0] {
		// match path BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/': // path
			ac = a[0]
			a = a[1:] // pass

		// match pct-encoded
		case '%':
			var err error
			ac, err = parseHex(a, 1)
			if err != nil {
				return false // invalid
			}
			a = a[3:] // pass
			aEscSep = ac == '/'

		default:
			return false // invalid
		}

		var bc byte
		var bEscSep bool
		switch b[0] {
		// match path BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/': // path
			bc = b[0]
			b = b[1:] // pass

		// match pct-encoded
		case '%':
			var err error
			bc, err = parseHex(b, 1)
			if err != nil {
				return false // invalid
			}
			b = b[3:] // pass
			bEscSep = bc == '/'

		default:
			return false // invalid
		}

		if ac != bc || aEscSep != bEscSep {
			return false // path mismatch
		}
	}
}

// String returns either the DID URL, or the empty string when zero. Any and
// all colon characters (':') in the method-specific identifier are escaped
// (with "%3A"). The return is invalid if any of the attributes (DID, RawPath,
// RawQuery or RawFragment) are invalid.
func (u *URL) String() string {
	return u.DID.String() + u.RawPath + u.RawQuery + u.RawFragment
}

func (u *URL) PathWithEscape(escape byte) string {
	s := u.RawPath
	i := 0
	for {
		if i >= len(s) {
			return s // fast path
		}

		if s[i] == escape || s[i] == '%' {
			break
		}

		i++
	}

	var b strings.Builder
	b.WriteString(s[:i])

	for i < len(s) {
		switch s[i] {
		case '%':
			c, err := parseHex(s, i+1)
			if err != nil {
				b.WriteByte(s[i])
				break
			}

			switch c {
			default:
				b.WriteByte(c)
			case escape:
				b.WriteByte(escape)
				b.WriteByte(escape)
			case '/':
				b.WriteByte(escape)
				b.WriteByte('/')
			}
			i += 3
			continue
		case escape:
			b.WriteByte(escape)
			b.WriteByte(escape)
		default:
			b.WriteByte(s[i])
		}
		i++
	}

	return b.String()
}

func (u *URL) PathSegments() []string {
	if u.RawPath == "" {
		return nil
	}

	s := strings.TrimPrefix(u.RawPath, "/")
	segs := make([]string, 0, strings.Count(s, "/"))

	// apply each directory
	for {
		i := strings.IndexByte(s, '/')
		if i < 0 {
			break
		}
		segs = append(segs, bestEffortDecode(s[:i]))
		s = s[i+1:]
	}

	// apply the last segment
	if s != "" {
		segs = append(segs, bestEffortDecode(s))
	}

	return segs
}

func (u *URL) SetPathSegments(segs ...string) {
	if len(segs) == 0 {
		u.RawPath = ""
		return
	}

	var b strings.Builder
	for _, s := range segs {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(s))
	}
	if segs[len(segs)-1] == "" {
		b.WriteByte('/')
	}
	u.RawPath = b.String()
}

// Query returns the encoded value from RawQuery, if any. Decoding is on
// best-effort basis. Malformed percent-encodings simply pass as is.
//
// None of the applicable standards put any constraints on the byte-content. The
// return may or may not be a valid UTF-8 string.
func (u *URL) Query() string {
	if u.RawQuery == "" || u.RawQuery[0] != '?' {
		return ""
	}
	return bestEffortDecode(u.RawQuery[1:])
}

// SetQuery sets RawQuery to contain a normalized encoding of s.
//
// None of the applicable standards put any constraints on the byte-content. S
// may or may not be a valid UTF-8 string.
func (u *URL) SetQuery(s string) {
	u.RawQuery = encodeWithLead(s, '?')
}

func (u *URL) Fragment() string {
	if u.RawFragment == "" || u.RawFragment[0] != '#' {
		return ""
	}
	return bestEffortDecode(u.RawFragment[1:])
}

func (u *URL) SetFragment(s string) {
	u.RawFragment = encodeWithLead(s, '#')
}

// MarshalJSON implements the json.Marshaler interface.
func (u *URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (u *URL) UnmarshalJSON(bytes []byte) error {
	var s string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}

	p, err := ParseURL(s)
	if err != nil {
		return fmt.Errorf("JSON string content: %w", err)
	}
	*u = *p // copy
	return nil
}

var (
	errVersionIDDupe   = errors.New("duplicate versionId in DID URL")
	errVersionTimeDupe = errors.New("duplicate versionTime in DID URL")
)

// VersionParams returns the standardised "versionId" and "versionTime".
func VersionParams(params url.Values) (string, time.Time, error) {
	var s string
	switch a := params["versionId"]; len(a) {
	case 0:
		break
	case 1:
		s = a[0]
	default:
		return "", time.Time{}, errVersionIDDupe
	}

	switch a := params["versionTime"]; len(a) {
	case 0:
		return s, time.Time{}, nil
	case 1:
		t, err := time.Parse(time.RFC3339, a[0])
		if err != nil {
			return "", time.Time{}, fmt.Errorf("versionTime in DID URL: %w", err)
		}
		return s, t, nil
	default:
		return "", time.Time{}, errVersionTimeDupe
	}
}

// SetVersionParams installs the standardised "versionId" and "versionTime". The
// zero value on either s or t clears the respective parameter.
func SetVersionParams(params url.Values, s string, t time.Time) {
	if s != "" {
		params.Set("versionId", s)
	} else {
		params.Del("versionId")
	}

	if !t.IsZero() {
		// JSON production requires “normalized to UTC 00:00:00 and
		// without sub-second decimal precision”, as per subsection
		// 6.2.1 of the v1 specification.
		t := t.UTC()
		if t.Nanosecond() != 0 {
			t = t.Round(time.Second)
		}
		params.Set("versionTime", t.Format(time.RFC3339))
	} else {
		params.Del("versionTime")
	}
}

// Malmormed percent-encodings simply pass as is.
func bestEffortDecode(s string) string {
	i := strings.IndexByte(s, '%')
	if i < 0 {
		return s // fast path
	}

	var b strings.Builder
	for ; i >= 0; i = strings.IndexByte(s, '%') {
		v, err := parseHex(s, i+1)
		if err != nil {
			b.WriteString(s[:i+1]) // all including the '%'
			s = s[i+1:]            // pass '%'
			continue
		}

		b.WriteString(s[:i]) // all before the '%'
		b.WriteByte(v)       // escaped value
		s = s[i+3:]          // pass '%' and both hex digits
	}
	b.WriteString(s)
	return b.String()
}

// EncodeWithLead returns s prefixed by lead, including percent-encoding where
// needed.
func encodeWithLead(s string, lead byte) string {
	var b strings.Builder
	b.WriteByte(lead)

	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		// match query or fragment BNF excluding pct-encoded
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // unreserved
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', // unreserved
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', // unreserved
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', // unreserved
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', // unreserved
			'-', '.', '_', '~', // unreserved
			'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', // sub-delims
			':', '@', // pchar
			'/', '?': // query or fragment
			// no escape
			b.WriteByte(c)

		default:
			// escape
			b.WriteByte('%')
			b.WriteByte(hexTable[c>>4])
			b.WriteByte(hexTable[c&15])
		}
	}

	return b.String()
}

// HexTable maps a nibble to its encoded value.
//
// “For consistency, URI producers and normalizers should use uppercase
// hexadecimal digits for all percent-encodings.”
// — “URI: Generic Syntax” RFC 3986, subsection 2.1
var hexTable = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}

// ParseHex returns the interpretation of two hex digits, starting at index i.
func parseHex(s string, i int) (byte, error) {
	var v byte

	if i >= len(s) {
		return 0, &SyntaxError{S: s, I: i}
	}
	switch c := s[i]; c {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		v = c - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		v = c - 'A' + 10
	case 'a', 'b', 'c', 'd', 'e', 'f':
		v = c - 'a' + 10
	default:
		return 0, &SyntaxError{S: s, I: i}
	}
	v <<= 4

	i++
	if i >= len(s) {
		return 0, &SyntaxError{S: s, I: i}
	}
	switch c := s[i]; c {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		v |= c - '0'
	case 'A', 'B', 'C', 'D', 'E', 'F':
		v |= c - 'A' + 10
	case 'a', 'b', 'c', 'd', 'e', 'f':
		v |= c - 'a' + 10
	default:
		return 0, &SyntaxError{S: s, I: i}
	}
	return v, nil
}
