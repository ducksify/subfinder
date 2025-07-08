package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ducksify/subfinder/v2/pkg/resolve"
)

func TestRunEnumerationResult(t *testing.T) {
	// Create options for subfinder
	options := &Options{
		Domain: []string{"example.com"},
		// Configure minimal options for testing
		Threads:            5,
		Timeout:            10,
		MaxEnumerationTime: 1,
		RateLimit:          50,
	}

	// Create a new runner
	r, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Could not create runner: %s", err)
	}

	// Run enumeration as library and get structured results
	results, err := r.RunEnumerationWithReturn()
	if err != nil {
		t.Fatalf("Could not run enumeration: %s", err)
	}

	// Basic validation of results structure
	if results == nil {
		t.Fatal("Results should not be nil")
	}

	if len(results.Results) == 0 {
		t.Log("No results found (this might be expected for example.com)")
		return
	}

	// Validate the first result
	result := results.Results[0]
	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", result.Domain)
	}

	if result.Duration == "" {
		t.Error("Duration should not be empty")
	}

	// Validate subdomains slice
	if result.Subdomains == nil {
		t.Error("Subdomains slice should not be nil")
	}

	// Validate host entries
	if result.HostEntries == nil {
		t.Error("HostEntries slice should not be nil")
	}

	// Validate source map
	if result.SourceMap == nil {
		t.Error("SourceMap should not be nil")
	}

	// Check that subdomains and host entries have the same length
	if len(result.Subdomains) != len(result.HostEntries) {
		t.Errorf("Subdomains count (%d) should match HostEntries count (%d)",
			len(result.Subdomains), len(result.HostEntries))
	}

	t.Logf("Successfully found %d subdomains for %s in %s",
		len(result.Subdomains), result.Domain, result.Duration)
}

func TestEnumerateSingleDomainResult(t *testing.T) {
	// Create options for subfinder
	options := &Options{
		Threads:            5,
		Timeout:            10,
		MaxEnumerationTime: 1,
		RateLimit:          50,
	}

	// Create a new runner
	r, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Could not create runner: %s", err)
	}

	// Test single domain enumeration
	result, err := r.EnumerateSingleDomainAsLibrary("example.com")
	if err != nil {
		t.Fatalf("Could not enumerate single domain: %s", err)
	}

	// Validate result structure
	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", result.Domain)
	}

	if result.Duration == "" {
		t.Error("Duration should not be empty")
	}

	if result.Subdomains == nil {
		t.Error("Subdomains slice should not be nil")
	}

	if result.HostEntries == nil {
		t.Error("HostEntries slice should not be nil")
	}

	if result.SourceMap == nil {
		t.Error("SourceMap should not be nil")
	}

	t.Logf("Successfully enumerated %d subdomains for %s in %s",
		len(result.Subdomains), result.Domain, result.Duration)
}

func TestEnumerateSingleDomainResultWithCtx(t *testing.T) {
	// Create options for subfinder
	options := &Options{
		Threads:            5,
		Timeout:            10,
		MaxEnumerationTime: 1,
		RateLimit:          50,
	}

	// Create a new runner
	r, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Could not create runner: %s", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test single domain enumeration with context
	result, err := r.EnumerateSingleDomainReturnWithCtx(ctx, "example.com")
	if err != nil {
		t.Fatalf("Could not enumerate single domain with context: %s", err)
	}

	// Validate result structure
	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", result.Domain)
	}

	t.Logf("Successfully enumerated %d subdomains for %s in %s",
		len(result.Subdomains), result.Domain, result.Duration)
}

func TestEnumerateMultipleDomainsResult(t *testing.T) {
	// Create options for subfinder
	options := &Options{
		Threads:            5,
		Timeout:            10,
		MaxEnumerationTime: 1,
		RateLimit:          50,
	}

	// Create a new runner
	r, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Could not create runner: %s", err)
	}

	// Create a reader with multiple domains
	domains := "example.com\ntest.com"
	reader := strings.NewReader(domains)

	// Test multiple domains enumeration
	results, err := r.EnumerateMultipleDomainsReturn(reader)
	if err != nil {
		t.Fatalf("Could not enumerate multiple domains: %s", err)
	}

	// Validate results structure
	if results == nil {
		t.Fatal("Results should not be nil")
	}

	if len(results.Results) == 0 {
		t.Log("No results found (this might be expected for test domains)")
		return
	}

	// Check that we have results for the domains we provided
	expectedDomains := map[string]bool{
		"example.com": false,
		"test.com":    false,
	}

	for _, result := range results.Results {
		if _, exists := expectedDomains[result.Domain]; exists {
			expectedDomains[result.Domain] = true
		}
	}

	for domain, found := range expectedDomains {
		if !found {
			t.Logf("No results found for domain %s (this might be expected)", domain)
		}
	}

	t.Logf("Successfully processed %d domain results", len(results.Results))
}

func TestEnumerationResultStructure(t *testing.T) {
	// Test the structure of EnumerationResult
	result := &EnumerationResult{
		Domain:     "test.com",
		Subdomains: []string{"www.test.com", "api.test.com"},
		HostEntries: []resolve.HostEntry{
			{Domain: "test.com", Host: "www.test.com", Source: "test-source"},
			{Domain: "test.com", Host: "api.test.com", Source: "test-source"},
		},
		SourceMap: map[string]map[string]struct{}{
			"www.test.com": {"test-source": {}},
			"api.test.com": {"test-source": {}},
		},
		Duration: "1s",
	}

	// Validate structure
	if result.Domain != "test.com" {
		t.Errorf("Expected domain 'test.com', got '%s'", result.Domain)
	}

	if len(result.Subdomains) != 2 {
		t.Errorf("Expected 2 subdomains, got %d", len(result.Subdomains))
	}

	if len(result.HostEntries) != 2 {
		t.Errorf("Expected 2 host entries, got %d", len(result.HostEntries))
	}

	if len(result.SourceMap) != 2 {
		t.Errorf("Expected 2 source map entries, got %d", len(result.SourceMap))
	}

	if result.Duration != "1s" {
		t.Errorf("Expected duration '1s', got '%s'", result.Duration)
	}

	t.Log("EnumerationResult structure validation passed")
}

func TestMultipleEnumerationResultStructure(t *testing.T) {
	// Test the structure of MultipleEnumerationResult
	results := &MultipleEnumerationResult{
		Results: []EnumerationResult{
			{
				Domain:     "test1.com",
				Subdomains: []string{"www.test1.com"},
				Duration:   "1s",
			},
			{
				Domain:     "test2.com",
				Subdomains: []string{"www.test2.com"},
				Duration:   "2s",
			},
		},
		Errors: []error{},
	}

	// Validate structure
	if len(results.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(results.Results))
	}

	if len(results.Errors) != 0 {
		t.Errorf("Expected 0 errors, got %d", len(results.Errors))
	}

	if results.Results[0].Domain != "test1.com" {
		t.Errorf("Expected first domain 'test1.com', got '%s'", results.Results[0].Domain)
	}

	if results.Results[1].Domain != "test2.com" {
		t.Errorf("Expected second domain 'test2.com', got '%s'", results.Results[1].Domain)
	}

	t.Log("MultipleEnumerationResult structure validation passed")
}

func TestRunEnumerationWithReturn(t *testing.T) {
	// Create options for subfinder
	options := &Options{
		Domain: []string{"example.com"},
		// Configure minimal options for testing
		Threads:            5,
		Timeout:            10,
		MaxEnumerationTime: 1,
		RateLimit:          50,
	}

	// Create a new runner
	r, err := NewRunner(options)
	if err != nil {
		t.Fatalf("Could not create runner: %s", err)
	}

	// Run enumeration as library and get structured results
	results, err := r.RunEnumerationWithReturn()
	if err != nil {
		t.Fatalf("Could not run enumeration: %s", err)
	}

	// Basic validation of results structure
	if results == nil {
		t.Fatal("Results should not be nil")
	}

	if len(results.Results) == 0 {
		t.Log("No results found (this might be expected for example.com)")
		return
	}

	// Validate the first result
	result := results.Results[0]
	if result.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got '%s'", result.Domain)
	}

	if result.Duration == "" {
		t.Error("Duration should not be empty")
	}

	// Validate subdomains slice
	if result.Subdomains == nil {
		t.Error("Subdomains slice should not be nil")
	}

	// Validate host entries
	if result.HostEntries == nil {
		t.Error("HostEntries slice should not be nil")
	}

	// Validate source map
	if result.SourceMap == nil {
		t.Error("SourceMap should not be nil")
	}

	// Check that subdomains and host entries have the same length
	if len(result.Subdomains) != len(result.HostEntries) {
		t.Errorf("Subdomains count (%d) should match HostEntries count (%d)",
			len(result.Subdomains), len(result.HostEntries))
	}

	t.Logf("Successfully found %d subdomains for %s in %s",
		len(result.Subdomains), result.Domain, result.Duration)
}
