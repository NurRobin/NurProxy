package main

import "testing"

func TestValidateRootHelperInvocation(t *testing.T) {
	if err := validateRootHelperInvocation(nil, 0); err != nil {
		t.Fatalf("root invocation rejected: %v", err)
	}
	if err := validateRootHelperInvocation([]string{"--config", "/tmp/untrusted"}, 0); err == nil {
		t.Fatal("root helper accepted caller-selected configuration")
	}
	if err := validateRootHelperInvocation(nil, 1000); err == nil {
		t.Fatal("root helper accepted non-root effective uid")
	}
}

func TestValidateHelperRefreshInvocation(t *testing.T) {
	if err := validateHelperRefreshInvocation(nil, 0, "dev-build"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		args  []string
		uid   int
		build string
	}{{[]string{"--config", "/tmp/other"}, 0, "dev-build"}, {nil, 1000, "dev-build"}, {nil, 0, ""}} {
		if err := validateHelperRefreshInvocation(test.args, test.uid, test.build); err == nil {
			t.Fatalf("unsafe helper refresh accepted: %+v", test)
		}
	}
}
