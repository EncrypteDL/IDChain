package backend

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Example2 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-2
const example2 = "did:example:123456/path"

// Example3 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-3
const example3 = "did:example:123456?versionId=1"

// Example4 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-unique-verification-method-in-a-did-document
const example4 = "did:example:123#public-key-0"

// Example5 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-unique-service-in-a-did-document
const example5 = "did:example:123#agent"

// Example6 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-resource-external-to-a-did-document
const example6 = "did:example:123?service=agent&relativeRef=/credentials#degree"

// Example7 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-did-url-with-a-versiontime-did-parameter
const example7 = "did:example:123?versionTime=2021-05-10T17:00:00Z"

// Example8 is borrowed from the W3C.
// https://www.w3.org/TR/did-core/#example-a-did-url-with-a-service-and-a-relativeref-did-parameter
const example8 = "did:example:123?service=files&relativeRef=/resume.pdf"

func ExampleParse_percentEncoding() {
	d, err := Parse("did:example:escaped%F0%9F%A4%96")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("parsed: " + d.SpecID)
	fmt.Println("string: " + d.String())
	// Output:
	// parsed: escaped🤖
	// string: did:example:escaped%F0%9F%A4%96
}

var GoldenDIDs = []struct {
	S string
	DID
}{
	{
		"did:foo:bar",
		DID{Method: "foo", SpecID: "bar"},
	}, {
		"did:foo:b%61r",
		DID{Method: "foo", SpecID: "bar"},
	}, {
		"did:c:str%00",
		DID{Method: "c", SpecID: "str\x00"},
	}, {
		"did:a:b:c",
		DID{Method: "a", SpecID: "b:c"},
	}, {
		"did:a:b%3Ac",
		DID{Method: "a", SpecID: "b:c"},
	}, {
		"did:a::c",
		DID{Method: "a", SpecID: ":c"},
	}, {
		"did:a:%3Ac",
		DID{Method: "a", SpecID: ":c"},
	}, {
		"did:a:::c",
		DID{Method: "a", SpecID: "::c"},
	}, {
		"did:h:%12:%34",
		DID{Method: "h", SpecID: "\x12:\x34"},
	}, {
		"did:x:%3A",
		DID{Method: "x", SpecID: ":"},
	}, {
		"did:xx::%3A",
		DID{Method: "xx", SpecID: "::"},
	}, {
		"did:xxx:%3A%3A",
		DID{Method: "xxx", SpecID: "::"},
	},
}

func TestParse(t *testing.T) {
	for _, gold := range GoldenDIDs {
		d, err := Parse(gold.S)
		switch {
		case err != nil:
			t.Errorf("%s got error: %s", gold.S, err)
		case d != gold.DID:
			t.Errorf("%s got %#v, want %#v", gold.S, d, gold.DID)
		}
	}
}

var GoldenDIDErrors = []struct{ DID, Err string }{
	{"", "empty DID string"},

	{"urn:issn:0-670-85668-1", `invalid DID "urn:issn:0-670-85668-1": no "did:" scheme`},
	{"bitcoin:mjSk1Ny9spzU2fouzYgLqGUD8U41iR35QN?amount=100", `invalid DID "bitcoin:mjSk1Ny9spzU2fouzYgLqGUD8U41iR35QN?amount=100": no "did:" scheme`},
	{"http://localhost/", `invalid DID "http://localhost/": no "did:" scheme`},

	{"did:", `invalid DID "did:": end incomplete`},
	{"did:foo", `invalid DID "did:foo": end incomplete`},
	{"did:foo:", `invalid DID "did:foo:": end incomplete`},
	{"did:foo:%", `invalid DID "did:foo:%": end incomplete`},
	{"did:foo:%b", `invalid DID "did:foo:%b": end incomplete`},

	{"did::bar", `invalid DID "did::bar": illegal ':' at byte № 5`},
	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:X:bar", `invalid DID "did:X:bar": illegal 'X' at byte № 5`},
	{"did:a-1:bar", `invalid DID "did:a-1:bar": illegal '-' at byte № 6`},
	{"did:f%6Fo:bar", `invalid DID "did:f%6Fo:bar": illegal '%' at byte № 6`},

	// colon in method-specific identifier not allowed as last character
	{"did:foo::", `invalid DID "did:foo::": illegal ':' at byte № 9`},
	{"did:foo:::", `invalid DID "did:foo:::": illegal ':' at byte № 10`},
	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:foo:bar::", `invalid DID "did:foo:bar::": illegal ':' at byte № 13`},
	{"did:foo:bar:baz:", `invalid DID "did:foo:bar:baz:": illegal ':' at byte № 16`},
	{"did:foo:%12:", `invalid DID "did:foo:%12:": illegal ':' at byte № 12`},
	{"did:foo:%3A:", `invalid DID "did:foo:%3A:": illegal ':' at byte № 12`},

	{"did:foo:bar:", `invalid DID "did:foo:bar:": illegal ':' at byte № 12`},
	{"did:foo:bar:,", `invalid DID "did:foo:bar:,": illegal ',' at byte № 13`},
	{"did:foo:bar:%X0", `invalid DID "did:foo:bar:%X0": illegal 'X' at byte № 14`},
	{"did:foo:bar:%0Y", `invalid DID "did:foo:bar:%0Y": illegal 'Y' at byte № 15`},

	{"did:long" + strings.Repeat("g", 1000), `invalid DID "did:longggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg…" [truncated]: end incomplete`},
	{"did:long" + strings.Repeat("g", 1000) + ":~", `invalid DID "did:longggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg…" [truncated]: illegal '~' at byte № 1010`},
}

func TestParseErrors(t *testing.T) {
	for _, gold := range GoldenDIDErrors {
		got, err := Parse(gold.DID)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.DID, got, gold.Err)
		case *SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.DID, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.DID, err, err)
		}
	}
}

func TestDIDString(t *testing.T) {
	if got := new(DID).String(); got != "" {
		t.Errorf("the zero value got %q, want an empty string", got)
	}

	for _, gold := range GoldenDIDs {
		var got string
		n := testing.AllocsPerRun(1, func() {
			got = gold.DID.String()
		})
		if n != 1 {
			t.Errorf("%#v String did %f memory allocations, want 1", gold.DID, n)
		}
		if !gold.DID.EqualString(got) {
			t.Errorf("%#v String got %q, want EqualString to self", gold.DID, got)
		}
	}
}

// DIDEquals groups equivalent DIDs.
var DIDEquals = [][]string{
	{
		"did:example:escaped%F0%9F%A4%96",
		"did:example:%65scaped%F0%9F%A4%96",
		"did:example:escap%65d%F0%9F%A4%96",
	},
	{
		"did:tricky:%3Afoo%2F",
		"did:tricky:%3A%66%6F%6F%2F",
	},
	{
		// binary value
		"did:sha256:%e3%b0%c4%42%98%fc%1c%14%9a%fb%f4%c8%99%6f%b9%24%27%ae%41%e4%64%9b%93%4c%a4%95%99%1b%78%52%b8%55",
		// upper- and lower-case mix
		"did:sha256:%E3%b0%c4%42%98%Fc%1c%14%9a%fB%f4%c8%99%6f%b9%24%27%ae%41%e4%64%9b%93%4c%a4%95%99%1b%78%52%b8%55",
	},
}

func TestDIDEqualString(t *testing.T) {
	for _, gold := range GoldenDIDs {
		if !gold.DID.EqualString(gold.S) {
			t.Errorf("%#v got false for %q, want true", gold.DID, gold.S)
		}
	}

	for i, equals := range DIDEquals {
		for _, s := range equals {
			d, err := Parse(s)
			if err != nil {
				t.Fatalf("Parse(%q) error: %s", s, err)
			}

			// compare all groups
			for j, equals := range DIDEquals {
				want := i == j // same group

				// compare each entry, including self
				for _, e := range equals {
					got := d.EqualString(e)
					if got != want {
						t.Errorf("Parse(%q) EqualString(%q) got %t, want %t\nparsed as %#v", s, e, got, want, d)
					}
				}
			}
		}
	}
}

var GoldenURLs = []struct {
	S string
	URL
}{
	{
		"did:example:123456789abcdefghi", // from example1
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123456789abcdefghi",
			},
		},
	}, {
		example2,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123456",
			},
			RawPath: "/path",
		},
	}, {
		example3,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123456",
			},
			RawQuery: "?versionId=1",
		},
	}, {
		example4,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123",
			},
			RawFragment: "#public-key-0",
		},
	}, {
		example5,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123",
			},
			RawFragment: "#agent",
		},
	}, {
		example6,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123",
			},
			RawQuery:    "?service=agent&relativeRef=/credentials",
			RawFragment: "#degree",
		},
	}, {
		example7,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123",
			},
			RawQuery: "?versionTime=2021-05-10T17:00:00Z",
		},
	}, {
		example8,
		URL{
			DID: DID{
				Method: "example",
				SpecID: "123",
			},
			RawQuery: "?service=files&relativeRef=/resume.pdf",
		},
	}, {
		"did:foo:bar:baz",
		URL{
			DID: DID{
				Method: "foo",
				SpecID: "bar:baz",
			},
		},
	},

	{"?", URL{RawQuery: "?"}},
	{"#", URL{RawFragment: "#"}},
	{"?#", URL{RawQuery: "?", RawFragment: "#"}},

	{".", URL{RawPath: "."}},
	{"./", URL{RawPath: "./"}},
	{"./..", URL{RawPath: "./.."}},
	{"./../", URL{RawPath: "./../"}},
	{"./../...", URL{RawPath: "./../..."}},
	{".#", URL{RawPath: ".", RawFragment: "#"}},
	{"./#", URL{RawPath: "./", RawFragment: "#"}},
	{"./..#", URL{RawPath: "./..", RawFragment: "#"}},
	{"./../#", URL{RawPath: "./../", RawFragment: "#"}},
	{"./../...#", URL{RawPath: "./../...", RawFragment: "#"}},
	{".?", URL{RawPath: ".", RawQuery: "?"}},
	{"./?", URL{RawPath: "./", RawQuery: "?"}},
	{"./..?", URL{RawPath: "./..", RawQuery: "?"}},
	{"./../?", URL{RawPath: "./../", RawQuery: "?"}},
	{"./../...?", URL{RawPath: "./../...", RawQuery: "?"}},

	{"did", URL{RawPath: "did"}},
	{"did/", URL{RawPath: "did/"}},
	{"did/a", URL{RawPath: "did/a"}},
	{"/did:a", URL{RawPath: "/did:a"}},
	{"/did:a/", URL{RawPath: "/did:a/"}},
	{"/did:a/did", URL{RawPath: "/did:a/did"}},

	{"?foo=bar", URL{RawQuery: "?foo=bar"}},
	{"#foo", URL{RawFragment: "#foo"}},

	{"%BE?%DE#%AD", URL{RawPath: "%BE", RawQuery: "?%DE", RawFragment: "#%AD"}},
}

func TestParseURL(t *testing.T) {
	for _, gold := range GoldenURLs {
		got, err := ParseURL(gold.S)
		if err != nil {
			t.Errorf("DID %q got error: %s", gold.S, err)
			continue
		}

		if *got != gold.URL {
			t.Errorf("DID %q got %#v, want %#v", gold.S, *got, gold.URL)
		}
	}
}

var GoldenURLErrors = []struct{ URL, Err string }{
	{"", "empty DID string"},
	{"did:foo:bar/%", `invalid DID "did:foo:bar/%": end incomplete`},
	{"did:foo:bar?%", `invalid DID "did:foo:bar?%": end incomplete`},
	{"did:foo:bar#%", `invalid DID "did:foo:bar#%": end incomplete`},
	{"did:foo:bar/%X0", `invalid DID "did:foo:bar/%X0": illegal 'X' at byte № 14`},
	{"did:foo:bar?%X0", `invalid DID "did:foo:bar?%X0": illegal 'X' at byte № 14`},
	{"did:foo:bar#%X0", `invalid DID "did:foo:bar#%X0": illegal 'X' at byte № 14`},
}

func TestParseURLErrors(t *testing.T) {
	// ParseURL should give the same error as Parse for plain DIDs.
	for _, gold := range GoldenDIDErrors {
		got, err := ParseURL(gold.DID)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.DID, got, gold.Err)
		case *SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.DID, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.DID, err, err)
		}
	}

	for _, gold := range GoldenURLErrors {
		got, err := ParseURL(gold.URL)
		switch err.(type) {
		case nil:
			t.Errorf("%q got %+v, want SyntaxError %q", gold.URL, got, gold.Err)
		case *SyntaxError:
			if s := err.Error(); s != gold.Err {
				t.Errorf("%q got error %q, want %q", gold.URL, s, gold.Err)
			}
		default:
			t.Errorf("%q got error type %T (%q), want a *did.SyntaxError", gold.URL, err, err)
		}
	}
}

// SelectEquals groups equivalent DID URL additions.
var SelectEquals = [][]string{
	{
		"/escaped%F0%9F%A4%96",
		"/%65scaped%F0%9F%A4%96",
		"/escap%65d%f0%9F%a4%96",
	},
	{
		"?escaped%F0%9F%A4%96",
		"?%65scaped%F0%9F%A4%96",
		"?escap%65d%f0%9f%a4%96",
	},
	{
		"#escaped%F0%9F%A4%96",
		"#%65scaped%F0%9F%A4%96",
		"#escap%65d%f0%9f%a4%96",
	},
	{
		"/%ee?%aa=%bb#%ff",
		"/%eE?%aA=%bB#%fF",
		"/%Ee?%Aa=%Bb#%Ff",
		"/%EE?%AA=%BB#%FF",
	},
}

var URLEquals = func() [][]string {
	// compile equality groups from DIDEquals and SelectEquals
	var groups [][]string
	for _, DIDs := range DIDEquals {
		for _, selects := range SelectEquals {
			// apply each selection on each DID
			equals := make([]string, 0, len(DIDs)*len(selects))
			for _, d := range DIDs {
				for _, sel := range selects {
					equals = append(equals, d+sel)
				}
			}

			groups = append(groups, equals)
		}
	}
	return groups
}()

func TestURLEqualString(t *testing.T) {
	for _, gold := range GoldenURLs {
		got := gold.URL.EqualString(gold.S)
		if gold.URL.IsRelative() {
			if got {
				t.Errorf("%#v got true for relative %q, want false", gold.URL, gold.S)
			}
		} else {
			if !got {
				t.Errorf("%#v got false for %q, want true", gold.URL, gold.S)
			}
		}
	}

	for i, equals := range URLEquals {
		for _, s := range equals {
			u, err := ParseURL(s)
			if err != nil {
				t.Fatalf("ParseURL(%q) error: %s", s, err)
			}

			// compare all groups
			for j, equals := range URLEquals {
				want := i == j // same group

				// compare each entry, including self
				for _, e := range equals {
					got := u.EqualString(e)
					if got != want {
						t.Errorf("ParseURL(%q) EqualString(%q) got %t, want %t\nparsed as %#v", s, e, got, want, u)
					}
				}
			}
		}
	}
}

func TestURLString(t *testing.T) {
	if got := new(URL).String(); got != "" {
		t.Errorf("the zero value got %q, want an empty string", got)
	}

	for _, gold := range GoldenURLs {
		s := gold.URL.String()
		u, err := ParseURL(s)
		if err != nil {
			t.Errorf("%#v String got %q, ParseURL error: %s", gold.URL, s, err)
		} else if *u != gold.URL {
			t.Errorf("ParseURL(%q) got %#v, want original %#v", s, u, gold.URL)
		}
	}
}

func ExampleURL_PathWithEscape() {
	u, err := ParseURL("did:example:123456/path%2Fesc")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(u.PathWithEscape('\\'))
	// Output: /path\/esc
}

func TestURLPathWithEscape(t *testing.T) {
	tests := []struct {
		escape    byte
		raw, want string
	}{
		{'\\', "", ""},
		{'\\', "/", "/"},
		{'\\', "//", "//"},
		{'\\', "/foo", "/foo"},
		{'\\', "/f%6Fo", "/foo"},
		{'\\', "%66%6F%6F", "foo"},

		// percent encoded–path separator
		{'\\', "%2F", `\/`},
		{'\\', "%a2", "\xa2"},
		{'\\', "%2F%2F", `\/\/`},
		{'\\', "%fF%Ff", "\xff\xff"},
		{'\\', "%2Ffoo", `\/foo`},
		{'\\', "/foo%2F", `/foo\/`},
		{'\\', "%2F%66%6F%6F%2F", `\/foo\/`},
		{'%', "%2F", `%/`},
		{'%', "%a2", "\xa2"},
		{'%', "%2F%2F", `%/%/`},
		{'%', "%fF%Ff", "\xff\xff"},
		{'%', "%2Ffoo", `%/foo`},
		{'%', "/foo%2F", `/foo%/`},
		{'%', "%2F%66%6F%6F%2F", `%/foo%/`},

		// percent-encoded escape
		{'\\', "%5C", `\\`},
		{'\\', "/%5C", `/\\`},
		{'\\', "%5C/", `\\/`},
		{'%', "%25", `%%`},
		{'%', "/%25", `/%%`},
		{'%', "%25/", `%%/`},

		// broken encodings
		{'\\', "/mis1%1", "/mis1%1"},
		{'\\', "/mis2%", "/mis2%"},
		{'\\', "/mi%ss", "/mi%ss"},
		{'%', "/mis1%1", "/mis1%1"},
		{'%', "/mis2%", "/mis2%"},
		{'%', "/mi%ss", "/mi%ss"},
	}

	for _, test := range tests {
		u := URL{RawPath: test.raw}
		got := u.PathWithEscape(test.escape)
		if got != test.want {
			t.Errorf("raw path %q with escape %q got %q, want %q",
				test.raw, test.escape, got, test.want)
		}
	}
}

func FuzzURLPathWithEscape(f *testing.F) {
	f.Add("%2f", byte('\\'))
	f.Add("%2F", byte('%'))
	f.Add("/%5C", byte('\\'))
	f.Add("%25/", byte('%'))
	f.Fuzz(func(t *testing.T, rawPath string, escape byte) {
		u := URL{RawPath: rawPath}
		got := u.PathWithEscape(escape)

		want, err := url.PathUnescape(rawPath)
		if err == nil {
			x := string([]byte{escape, escape, '/'})
			unesc := strings.NewReplacer(x[:2], x[1:2], x[1:3], x[2:3]).Replace(got)
			if unesc != want {
				t.Logf("test %q unescaped to %q for comparison", rawPath, want)
				t.Logf("result %q unescaped to %q for comparison", got, unesc)
				t.Errorf("path %q with escape %q got %q", rawPath, escape, got)
			}
		}
	})
}

func ExampleURL_PathSegments() {
	u := URL{RawPath: "/plain/and%2For/escaped%20%E2%9C%A8"}
	fmt.Printf("segmented: %q\n", u.PathSegments())
	// Output: segmented: ["plain" "and/or" "escaped ✨"]
}

func ExampleURL_SetPathSegments() {
	var u URL
	u.SetPathSegments("plain", "and/or", "escaped ✨")
	fmt.Printf("raw path: %q\n", u.RawPath)
	// Output: raw path: "/plain/and%2For/escaped%20%E2%9C%A8"
}

func TestURLPathSegments(t *testing.T) {
	tests := []struct {
		rawPath string
		want    []string
	}{
		{"", nil},
		{"/", []string{}},
		{"//", []string{""}},
		{"/a", []string{"a"}},
		{"/a/", []string{"a"}},
		{"/a//", []string{"a", ""}},
		{"//b/", []string{"", "b"}},
		{"///", []string{"", ""}},
		{"/%AB/%ba/", []string{"\xab", "\xba"}},
		{"/%cD/%Dc/", []string{"\xcd", "\xdc"}},
	}
	for _, test := range tests {
		got := (&URL{RawPath: test.rawPath}).PathSegments()
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("raw path %q got %q, want %q", test.rawPath, got, test.want)
		}
	}
}

// FuzzURLSetPathSegments validates the SetPathSegments–GetPathSegments round-
// trip for losslessness.
func FuzzURLSetPathSegments(f *testing.F) {
	// Fuzz does not support []string yet
	f.Add("", "/", "")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		testURLSetPathSegments(t, a)
		testURLSetPathSegments(t, a, b)
		testURLSetPathSegments(t, a, b, c)
	})
}

func testURLSetPathSegments(t *testing.T, segs ...string) {
	var u URL
	u.SetPathSegments(segs...)
	got := u.PathSegments()
	if len(got) != len(segs) {
		t.Fatalf("got segments %q, want %q", got, segs)
	}
	for i, s := range segs {
		if s != got[i] {
			t.Fatalf("got segments %q, want %q", got, segs)
		}
	}
}

func TestURLVersionParams(t *testing.T) {
	t.Run("ID", func(t *testing.T) {
		sample := example3
		const want = "1"

		u, err := url.Parse(sample)
		if err != nil {
			t.Fatalf("%s parse error: %s", sample, err)
		}

		vID, vTime, err := VersionParams(u.Query())
		if err != nil {
			t.Fatalf("%s got error: %s", sample, err)
		}
		if vID != want {
			t.Errorf("%s got ID %q, want %q", sample, vID, want)
		}
		if !vTime.IsZero() {
			t.Errorf("%s got time %s, want zero", sample, vTime)
		}
	})

	t.Run("time", func(t *testing.T) {
		sample := example7
		want := time.Date(2021, 05, 10, 17, 00, 00, 0, time.UTC)

		u, err := url.Parse(sample)
		if err != nil {
			t.Fatalf("%s parse error: %s", sample, err)
		}

		vID, vTime, err := VersionParams(u.Query())
		if err != nil {
			t.Fatalf("%s got error: %s", sample, err)
		}
		if vID != "" {
			t.Errorf("%s got ID %q, want zero", sample, vID)
		}
		if !vTime.Equal(want) {
			t.Errorf("%s got time %s, want %s", sample, vTime, want)
		}
		if name, _ := vTime.Zone(); name != "UTC" {
			t.Errorf("%s got time zone %q, want UTC", sample, name)
		}
	})
}

func FuzzParseURL(f *testing.F) {
	f.Add("did:a:b/c?d#e")
	f.Fuzz(func(t *testing.T, s string) {
		_, parseErr := Parse(s)
		switch e := parseErr.(type) {
		case nil:
			break // OK
		case *SyntaxError:
			if e.S != s {
				t.Errorf("Parse(%q) got SyntaxError.S %q", s, e.S)
			}
			if !utf8.ValidString(parseErr.Error()) {
				t.Errorf("Parse(%q) error %q contains invalid UTF-8", s, parseErr)
			}
		default:
			t.Errorf("Parse(%q) got error type %T (%q), want a *did.SyntaxError", s, parseErr, parseErr)
		}

		_, parseURLErr := ParseURL(s)
		switch e := parseURLErr.(type) {
		case nil:
			if parseURLErr != nil {
				t.Errorf("ParseURL(%q) got no error, while Parse got error: %s", s, parseErr)
			}
		case *SyntaxError:
			if e.S != s {
				t.Errorf("ParseURL(%q) got SyntaxError.S %q", s, e.S)
			}
			if !utf8.ValidString(parseURLErr.Error()) {
				t.Errorf("ParseURL(%q) error %q contains invalid UTF-8", s, parseURLErr)
			}
			if parseErr == nil {
				t.Errorf("ParseURL(%q) got error %q, while Parse got no error", s, parseURLErr)
			}
		default:
			t.Errorf("ParseURL(%q) got error type %T (%q), want a *did.SyntaxError", s, parseURLErr, parseURLErr)
		}
	})
}
