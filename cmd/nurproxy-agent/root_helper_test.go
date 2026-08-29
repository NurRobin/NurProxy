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
