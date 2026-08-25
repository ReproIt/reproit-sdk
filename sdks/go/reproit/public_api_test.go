package reproit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"reproit.dev/sdk-go/reproit"
)

func TestPublicOperationAPIExcludesSharedEngineInternals(t *testing.T) {
	assertMethodNames(t, reflect.TypeOf((*reproit.AutomaticProject)(nil)), []string{
		"Close", "StartOperation", "StartOperationContext",
	})
	assertMethodNames(t, reflect.TypeOf((*reproit.AutomaticOperation)(nil)), []string{
		"Cancel", "Close", "Fail", "OperationID", "RecordInput", "Succeed",
	})
	for _, name := range exportedPackageNames(t) {
		for _, forbidden := range []string{
			"SDKEngine", "ObservationAdapter", "ObservationSession", "InstalledObservation",
			"NativeHandle",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("The Go SDK exports shared-engine internal %q.", name)
			}
		}
	}
}

func assertMethodNames(t *testing.T, value reflect.Type, expected []string) {
	t.Helper()
	actual := make([]string, value.NumMethod())
	for index := 0; index < value.NumMethod(); index++ {
		actual[index] = value.Method(index).Name
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("The public method set changed: got %v, want %v.", actual, expected)
	}
}

func exportedPackageNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal("The Go public API source is unavailable.")
	}
	set := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, parseErr := parser.ParseFile(set, entry.Name(), nil, 0)
		if parseErr != nil {
			t.Fatal("The Go public API source could not be parsed.")
		}
		for _, declaration := range file.Decls {
			switch typed := declaration.(type) {
			case *ast.FuncDecl:
				if typed.Recv == nil && ast.IsExported(typed.Name.Name) {
					names = append(names, typed.Name.Name)
				}
			case *ast.GenDecl:
				for _, specification := range typed.Specs {
					names = append(names, exportedSpecificationNames(specification)...)
				}
			}
		}
	}
	return names
}

func exportedSpecificationNames(specification ast.Spec) []string {
	switch typed := specification.(type) {
	case *ast.TypeSpec:
		if ast.IsExported(typed.Name.Name) {
			return []string{typed.Name.Name}
		}
	case *ast.ValueSpec:
		var names []string
		for _, name := range typed.Names {
			if ast.IsExported(name.Name) {
				names = append(names, name.Name)
			}
		}
		return names
	}
	return nil
}
