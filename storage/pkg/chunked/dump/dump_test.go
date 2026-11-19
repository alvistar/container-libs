//go:build unix

package dump

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"

	"go.podman.io/storage/pkg/chunked/internal/minimal"
)

func TestEscaped(t *testing.T) {
	tests := []struct {
		input  string
		escape int
		want   string
	}{
		{"12345", 0, "12345"},
		{"", 0, ""},
		{"\n", 0, "\\n"},
		{"\r", 0, "\\r"},
		{"\t", 0, "\\t"},
		{"\\", 0, "\\\\"},
		{"=", 0, "="},
		{"foo=bar", ESCAPE_EQUAL, "foo\\x3dbar"},
		{"-", ESCAPE_LONE_DASH, "\\x2d"},
		{"\n", NOESCAPE_SPACE, "\\n"},
		{" ", 0, "\\x20"},
		{" ", NOESCAPE_SPACE, " "},
		{"\t", NOESCAPE_SPACE, "\\t"},
		{"\n\t", NOESCAPE_SPACE, "\\n\\t"},
		{"Hello World!", 0, "Hello\\x20World!"},
		{"Hello World!", NOESCAPE_SPACE, "Hello World!"},
		{"NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt", 0, `NetLock_Arany_=Class_Gold=_F\xc5\x91tan\xc3\xbas\xc3\xadtv\xc3\xa1ny.crt`},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := escaped([]byte(test.input), test.escape)
			if result != test.want {
				t.Errorf("got %q, want %q", result, test.want)
			}
		})
	}
}

func TestDumpNode(t *testing.T) {
	modTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	regularFileEntry := &minimal.FileMetadata{
		Name:     "example.txt",
		Size:     100,
		Type:     minimal.TypeReg,
		UID:      1000,
		GID:      1000,
		Devmajor: 0,
		Devminor: 0,
		ModTime:  &modTime,
		Linkname: "",
		Digest:   "sha256:0123456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef",
		Xattrs: map[string]string{
			"user.key1": base64.StdEncoding.EncodeToString([]byte("value1")),
		},
	}

	rootEntry := &minimal.FileMetadata{
		Name:    "./",
		Type:    minimal.TypeDir,
		ModTime: &modTime,
		UID:     0,
	}

	rootEntry2 := &minimal.FileMetadata{
		Name:    "./",
		Type:    minimal.TypeDir,
		ModTime: &modTime,
		UID:     101,
	}

	directoryEntry := &minimal.FileMetadata{
		Name:     "mydir",
		Type:     minimal.TypeDir,
		UID:      1000,
		GID:      1000,
		ModTime:  &modTime,
		Linkname: "",
		Xattrs: map[string]string{
			"user.key2": base64.StdEncoding.EncodeToString([]byte("value2")),
		},
	}

	symlinkEntry := &minimal.FileMetadata{
		Name:     "mysymlink",
		Type:     minimal.TypeSymlink,
		ModTime:  &modTime,
		Linkname: "targetfile",
	}

	hardlinkEntry := &minimal.FileMetadata{
		Name:     "myhardlink",
		Type:     minimal.TypeLink,
		ModTime:  &modTime,
		Linkname: "existingfile",
	}

	missingParentEntry := &minimal.FileMetadata{
		Name:    "foo/bar/baz/entry",
		Type:    minimal.TypeReg,
		ModTime: &modTime,
	}

	testCases := []struct {
		name                string
		entries             []*minimal.FileMetadata
		expected            string
		skipAddingRootEntry bool
		expectError         bool
		verityDigests       map[string]string
	}{
		{
			name: "root entry",
			entries: []*minimal.FileMetadata{
				rootEntry,
			},
			expected:            "/ 0 40000 1 0 0 0 1672531200.0 - - -\n",
			skipAddingRootEntry: true,
		},
		{
			name: "duplicate root entry",
			entries: []*minimal.FileMetadata{
				rootEntry,
				rootEntry,
				rootEntry,
			},
			expected:            "/ 0 40000 1 0 0 0 1672531200.0 - - -\n",
			skipAddingRootEntry: true,
		},
		{
			name: "duplicate root entry with mismatch",
			entries: []*minimal.FileMetadata{
				rootEntry,
				rootEntry2,
			},
			skipAddingRootEntry: true,
			expectError:         true,
		},
		{
			name: "regular file",
			entries: []*minimal.FileMetadata{
				regularFileEntry,
			},
			expected: "/example.txt 100 100000 1 1000 1000 0 1672531200.0 01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef - - user.key1=value1\n",
		},
		{
			name: "regular file with verity",
			entries: []*minimal.FileMetadata{
				regularFileEntry,
			},
			verityDigests: map[string]string{
				"/01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef": "f4499a32b0292945caa054fe7a01780089da44b1cd9b1acf7c51bc21e5748b64",
			},
			expected: "/example.txt 100 100000 1 1000 1000 0 1672531200.0 01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef - f4499a32b0292945caa054fe7a01780089da44b1cd9b1acf7c51bc21e5748b64 user.key1=value1\n",
		},
		{
			name: "root entry with file",
			entries: []*minimal.FileMetadata{
				rootEntry,
				regularFileEntry,
			},
			expected:            "/ 0 40000 1 0 0 0 1672531200.0 - - -\n/example.txt 100 100000 1 1000 1000 0 1672531200.0 01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef - - user.key1=value1\n",
			skipAddingRootEntry: true,
		},
		{
			name: "root entry with file and verity",
			entries: []*minimal.FileMetadata{
				rootEntry,
				regularFileEntry,
			},
			verityDigests: map[string]string{
				"/01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef": "f4499a32b0292945caa054fe7a01780089da44b1cd9b1acf7c51bc21e5748b64",
			},
			expected:            "/ 0 40000 1 0 0 0 1672531200.0 - - -\n/example.txt 100 100000 1 1000 1000 0 1672531200.0 01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef - f4499a32b0292945caa054fe7a01780089da44b1cd9b1acf7c51bc21e5748b64 user.key1=value1\n",
			skipAddingRootEntry: true,
		},
		{
			name: "directory",
			entries: []*minimal.FileMetadata{
				directoryEntry,
			},
			expected: "/mydir 0 40000 1 1000 1000 0 1672531200.0 - - - user.key2=value2\n",
		},
		{
			name: "symlink",
			entries: []*minimal.FileMetadata{
				symlinkEntry,
			},
			expected: "/mysymlink 0 120000 1 0 0 0 1672531200.0 targetfile - -\n",
		},
		{
			name: "hardlink",
			entries: []*minimal.FileMetadata{
				hardlinkEntry,
			},
			expected: "/myhardlink 0 @100000 1 0 0 0 1672531200.0 /existingfile - -\n",
		},
		{
			name: "missing parent",
			entries: []*minimal.FileMetadata{
				missingParentEntry,
			},
			expected: "/foo 0 40755 1 0 0 0 0.0 - - -\n/foo/bar 0 40755 1 0 0 0 0.0 - - -\n/foo/bar/baz 0 40755 1 0 0 0 0.0 - - -\n/foo/bar/baz/entry 0 100000 1 0 0 0 1672531200.0 - - -\n",
		},
		{
			name: "complex case",
			entries: []*minimal.FileMetadata{
				rootEntry,
				regularFileEntry,
				directoryEntry,
			},
			expected:            "/ 0 40000 1 0 0 0 1672531200.0 - - -\n/example.txt 100 100000 1 1000 1000 0 1672531200.0 01/23456789abcdef1123456789abcdef2123456789abcdef3123456789abcdef - - user.key1=value1\n/mydir 0 40000 1 1000 1000 0 1672531200.0 - - - user.key2=value2\n",
			skipAddingRootEntry: true,
		},
	}

	for _, testCase := range testCases {
		var buf bytes.Buffer

		added := map[string]*minimal.FileMetadata{}
		if !testCase.skipAddingRootEntry {
			added["/"] = rootEntry
		}
		var foundErr error
		for _, entry := range testCase.entries {
			err := dumpNode(&buf, added, map[string]int{}, testCase.verityDigests, entry)
			if err != nil {
				foundErr = err
			}
		}
		if testCase.expectError && foundErr == nil {
			t.Errorf("expected error for %s, got nil", testCase.name)
		}
		if !testCase.expectError {
			if foundErr != nil {
				t.Errorf("unexpected error for %s: %v", testCase.name, foundErr)
			}
			actual := buf.String()
			if actual != testCase.expected {
				t.Errorf("for %s, got %q, want %q", testCase.name, actual, testCase.expected)
			}
		}
	}
}

func TestGenerateDumpWhiteouts(t *testing.T) {
	modTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	toc := &minimal.TOC{
		Entries: []minimal.FileMetadata{
			{Name: "./", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "UIpackage/", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "UIpackage/.wh.FlexUI.exe", Type: minimal.TypeReg, Mode: 0o644, UID: 1000, GID: 1000, ModTime: &modTime},
			{Name: "opq/", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "opq/.wh..wh..opq", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: "opq/new", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			// The opaque marker can come without an entry for its directory.
			{Name: "implicit/.wh..wh..opq", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			// A whiteout below a whiteout is dropped, as the non-composefs path does on ENOTDIR.
			{Name: ".wh.gone", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: "gone/.wh.child", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
		},
	}
	expected := "/ 0 40755 1 0 0 0 1672531200.0 - - -\n" +
		"/UIpackage 0 40755 1 0 0 0 1672531200.0 - - -\n" +
		"/UIpackage/FlexUI.exe 0 20000 1 1000 1000 0 1672531200.0 - - -\n" +
		"/opq 0 40755 1 0 0 0 1672531200.0 - - - trusted.overlay.opaque=y\n" +
		"/opq/new 0 100644 1 0 0 0 1672531200.0 - - -\n" +
		"/implicit 0 40755 1 0 0 0 0.0 - - - trusted.overlay.opaque=y\n" +
		"/gone 0 20000 1 0 0 0 1672531200.0 - - -\n"

	r, err := GenerateDump(toc, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if actual := buf.String(); actual != expected {
		t.Errorf("got:\n%s\nwant:\n%s", actual, expected)
	}

	// TOC entries are not changed: the TOC is also stored with the layer.
	if toc.Entries[2].Name != "UIpackage/.wh.FlexUI.exe" || toc.Entries[3].Xattrs != nil {
		t.Errorf("GenerateDump changed the TOC: %+v %+v", toc.Entries[2], toc.Entries[3])
	}
}

func generateDumpString(t *testing.T, toc *minimal.TOC) string {
	t.Helper()
	r, err := GenerateDump(toc, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestGenerateDumpWhiteoutInOpaqueDir(t *testing.T) {
	// mkcomposefs marks a directory holding a whiteout with an opaque value
	// that replaces "y", so the lower entries would show again.  The opaque
	// directory already hides them: the whiteout is dropped.
	modTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	toc := &minimal.TOC{
		Entries: []minimal.FileMetadata{
			{Name: "./", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "opq/", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "opq/.wh..wh..opq", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: "opq/.wh.old", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: "opq/sub/", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "opq/sub/.wh.deep", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
		},
	}
	expected := "/ 0 40755 1 0 0 0 1672531200.0 - - -\n" +
		"/opq 0 40755 1 0 0 0 1672531200.0 - - - trusted.overlay.opaque=y\n" +
		"/opq/sub 0 40755 1 0 0 0 1672531200.0 - - -\n"

	if actual := generateDumpString(t, toc); actual != expected {
		t.Errorf("got:\n%s\nwant:\n%s", actual, expected)
	}

	// Overlay always merges the root of a layer, so an opaque root hides
	// nothing and a whiteout at the root is kept.
	toc = &minimal.TOC{
		Entries: []minimal.FileMetadata{
			{Name: "./", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: ".wh..wh..opq", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: ".wh.old", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
		},
	}
	expected = "/ 0 40755 1 0 0 0 1672531200.0 - - - trusted.overlay.opaque=y\n" +
		"/old 0 20000 1 0 0 0 1672531200.0 - - -\n"
	if actual := generateDumpString(t, toc); actual != expected {
		t.Errorf("got:\n%s\nwant:\n%s", actual, expected)
	}
}

func TestGenerateDumpWhiteoutReplaced(t *testing.T) {
	// A whiteout applies to the lower layers only: an entry of the same layer
	// with its name stays, and a directory hides the lower one as a whole.
	modTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	toc := &minimal.TOC{
		Entries: []minimal.FileMetadata{
			{Name: "./", Type: minimal.TypeDir, Mode: 0o755, ModTime: &modTime},
			{Name: "file", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: ".wh.file", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: ".wh.dir", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
			{Name: "dir/", Type: minimal.TypeDir, Mode: 0o700, ModTime: &modTime},
			{Name: "dir/new", Type: minimal.TypeReg, Mode: 0o644, ModTime: &modTime},
		},
	}
	expected := "/ 0 40755 1 0 0 0 1672531200.0 - - -\n" +
		"/file 0 100644 1 0 0 0 1672531200.0 - - -\n" +
		"/dir 0 40700 1 0 0 0 1672531200.0 - - - trusted.overlay.opaque=y\n" +
		"/dir/new 0 100644 1 0 0 0 1672531200.0 - - -\n"

	if actual := generateDumpString(t, toc); actual != expected {
		t.Errorf("got:\n%s\nwant:\n%s", actual, expected)
	}
}

func TestGenerateDumpWhiteoutInvalid(t *testing.T) {
	for _, name := range []string{"a/.wh.", "a/.wh..", "a/.wh..."} {
		toc := &minimal.TOC{Entries: []minimal.FileMetadata{{Name: name, Type: minimal.TypeReg}}}
		r, err := GenerateDump(toc, nil)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		// The targets are "", "." and "..".
		if _, err := buf.ReadFrom(r); err == nil {
			t.Errorf("%q: expected an error, got dump %q", name, buf.String())
		}
	}
}
