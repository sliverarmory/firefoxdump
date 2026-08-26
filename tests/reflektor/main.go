//go:build windows && (386 || amd64)

// Command reflektor-smoke validates the packaged FirefoxDump BOF through the
// same public Reflektor API used by Sliver's built-in BOF executor.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/sliverarmory/reflektor/bof"
)

const expectedNoProfileSuffix = "\n[*] Extracting Firefox Data from All Profiles\n" +
	"================================\n" +
	"[!] No Firefox profiles found\n"

const sqliteUnavailablePrefix = "[!] Failed to load SQLite DLL. Make sure winsqlite3.dll is available.\n" +
	"[!] Cookie extraction and legacy signons.sqlite will not work.\n"

const invalidArgumentsOutput = "[!] Invalid BOF arguments; expected one --mode string.\n"

type smokeCase struct {
	name     string
	option   string
	noFields bool
	raw      []byte
	expected string
}

func main() {
	objectPath := flag.String("object", "", "path to the native-architecture FirefoxDump COFF object")
	flag.Parse()

	if *objectPath == "" {
		fatalf("-object is required")
	}
	if err := guardNoFirefoxProfiles(); err != nil {
		fatalf("credential-safety guard: %v", err)
	}

	cases := []smokeCase{
		{name: "no-fields", noFields: true},
		{name: "default", option: ""},
		{name: "cookies", option: "/cookies"},
		{name: "all", option: "/all"},
		{name: "invalid", option: "bogus", expected: "[!] Invalid mode. Use --mode /all or --mode /cookies.\n"},
		{name: "oversized", option: strings.Repeat("a", 255), expected: invalidArgumentsOutput},
		{name: "malformed", raw: []byte{5, 0, 0, 0, 2, 0, 0, 0, 'x'}, expected: invalidArgumentsOutput},
	}
	for _, testCase := range cases {
		if err := runSmokeCase(*objectPath, testCase); err != nil {
			fatalf("%s: %v", testCase.name, err)
		}
		fmt.Printf("ok: windows/%s go %s\n", runtime.GOARCH, testCase.name)
	}
}

func runSmokeCase(objectPath string, testCase smokeCase) error {
	var imports []bof.Import
	object, err := bof.LoadFileWithOptions(objectPath, bof.LoadOptions{
		ValidateImports: func(snapshot []bof.Import) error {
			imports = append(imports, snapshot...)
			for _, imported := range snapshot {
				if imported.RequiresHost {
					return fmt.Errorf("import %q requires a host callback unavailable in Sliver's Reflektor executor", imported.Name)
				}
			}
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("load BOF: %w", err)
	}
	defer func() { _ = object.Close() }()
	if err := requireBuiltinCallbacks(imports); err != nil {
		return err
	}

	// Sliver packs an omitted optional string as a typed empty string, so the
	// default case deliberately exercises AddString("") rather than raw bytes.
	var arguments bof.Arguments
	argumentBytes := testCase.raw
	if argumentBytes == nil && !testCase.noFields {
		if err := arguments.AddString(testCase.option); err != nil {
			return fmt.Errorf("pack option: %w", err)
		}
	}
	if argumentBytes == nil {
		argumentBytes = arguments.Bytes()
	}
	outputs, err := object.Execute(argumentBytes)
	if err != nil {
		return fmt.Errorf("execute BOF: %w", err)
	}
	if len(outputs) == 0 {
		return errors.New("callback count = 0, want at least one BeaconOutput record")
	}
	var combined bytes.Buffer
	for index, output := range outputs {
		if output.Type != bof.OutputDefault {
			return fmt.Errorf("callback %d type = %#x, want OutputDefault (%#x)", index, output.Type, bof.OutputDefault)
		}
		combined.Write(output.Data)
	}
	payload := combined.Bytes()
	if bytes.IndexByte(payload, 0) >= 0 {
		return errors.New("BeaconOutput contains an embedded NUL")
	}

	output := string(payload)
	if testCase.expected != "" {
		if output != testCase.expected {
			return fmt.Errorf("unexpected callback payload %q, want %q", output, testCase.expected)
		}
		return nil
	}
	expected := expectedNoProfileOutput(testCase.option)
	if output != expected && output != sqliteUnavailablePrefix+expected {
		return fmt.Errorf("unexpected no-profile callback payload %q", output)
	}
	return nil
}

func expectedNoProfileOutput(option string) string {
	mode := "passwords only"
	switch option {
	case "/all":
		mode = "passwords and cookies"
	case "/cookies":
		mode = "cookies only"
	}
	return "\n[*] Extraction mode: " + mode + "\n" + expectedNoProfileSuffix
}

func requireBuiltinCallbacks(imports []bof.Import) error {
	required := map[string]bool{
		"BeaconDataExtract": false,
		"BeaconDataParse":   false,
		"BeaconOutput":      false,
	}
	for _, imported := range imports {
		for callback := range required {
			if strings.Contains(imported.Name, callback) {
				if !imported.Builtin {
					return fmt.Errorf("callback %q is not implemented by Reflektor", imported.Name)
				}
				required[callback] = true
			}
		}
	}
	var missing []string
	for callback, found := range required {
		if !found {
			missing = append(missing, callback)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("BOF does not import expected callbacks: %s", strings.Join(missing, ", "))
	}
	return nil
}

// guardNoFirefoxProfiles must run before loading or executing the BOF. The BOF
// can enumerate every C:\Users profile when elevated, so the guard checks both
// that hard-coded search space and the current user's resolved config path.
func guardNoFirefoxProfiles() error {
	candidates, err := filepath.Glob(`C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles`)
	if err != nil {
		return fmt.Errorf("enumerate Windows profile roots: %w", err)
	}
	configDirectory, configErr := os.UserConfigDir()
	if configErr != nil {
		return fmt.Errorf("resolve current user config directory: %w", configErr)
	}
	candidates = append(candidates, filepath.Join(configDirectory, "Mozilla", "Firefox", "Profiles"))

	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		cleaned := filepath.Clean(candidate)
		key := strings.ToLower(cleaned)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		info, statErr := os.Stat(cleaned)
		switch {
		case statErr == nil:
			return fmt.Errorf("refusing to execute because Firefox profile root %q exists (%s)", cleaned, info.Mode())
		case errors.Is(statErr, os.ErrNotExist):
			continue
		default:
			return fmt.Errorf("inspect Firefox profile root %q: %w", cleaned, statErr)
		}
	}
	return nil
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "reflektor-smoke: "+format+"\n", arguments...)
	os.Exit(1)
}
