package runner

import (
	"bufio"
	"context"
	"io"
	"math"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hako/durafmt"
	"github.com/projectdiscovery/gologger"
	contextutil "github.com/projectdiscovery/utils/context"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"

	"github.com/ducksify/subfinder/v2/pkg/passive"
	"github.com/ducksify/subfinder/v2/pkg/resolve"
	"github.com/ducksify/subfinder/v2/pkg/subscraping"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	passiveAgent   *passive.Agent
	resolverClient *resolve.Resolver
	rateLimit      *subscraping.CustomRateLimit
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()
	runner := &Runner{options: options}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine()

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	// Initialize the custom rate limit
	runner.rateLimit = &subscraping.CustomRateLimit{
		Custom: mapsutil.SyncLockMap[string, uint]{
			Map: make(map[string]uint),
		},
	}

	for source, sourceRateLimit := range options.RateLimits.AsMap() {
		if sourceRateLimit.MaxCount > 0 && sourceRateLimit.MaxCount <= math.MaxUint {
			_ = runner.rateLimit.Custom.Set(source, sourceRateLimit.MaxCount)
		}
	}

	return runner, nil
}

// RunEnumeration wraps RunEnumerationWithCtx with an empty context
func (r *Runner) RunEnumeration() error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithCtx(ctx)
}

// RunEnumerationWithCtx runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		if closeErr := f.Close(); closeErr != nil {
			gologger.Error().Msgf("Error closing file %s: %s", r.options.DomainsFile, closeErr)
		}
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerationResult represents the result of subdomain enumeration for a single domain
type EnumerationResult struct {
	Domain      string                            `json:"domain"`
	Subdomains  []string                          `json:"subdomains"`
	HostEntries []resolve.HostEntry               `json:"host_entries"`
	SourceMap   map[string]map[string]struct{}    `json:"source_map"`
	Statistics  map[string]subscraping.Statistics `json:"statistics,omitempty"`
	Duration    string                            `json:"duration"`
	Error       error                             `json:"error,omitempty"`
}

// MultipleEnumerationResult represents the result of subdomain enumeration for multiple domains
type MultipleEnumerationResult struct {
	Results []EnumerationResult `json:"results"`
	Errors  []error             `json:"errors,omitempty"`
}

// RunEnumerationWithReturn runs the subdomain enumeration and returns structured results
// This method is designed for library usage, returning data objects instead of writing to files
func (r *Runner) RunEnumerationWithReturn() (*MultipleEnumerationResult, error) {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.RunEnumerationWithReturnWithCtx(ctx)
}

// RunEnumerationWithReturnWithCtx runs the subdomain enumeration with context and returns structured results
func (r *Runner) RunEnumerationWithReturnWithCtx(ctx context.Context) (*MultipleEnumerationResult, error) {
	result := &MultipleEnumerationResult{
		Results: []EnumerationResult{},
		Errors:  []error{},
	}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsReturnWithCtx(ctx, domainsReader)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := f.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", r.options.DomainsFile, closeErr)
			}
		}()
		return r.EnumerateMultipleDomainsReturnWithCtx(ctx, f)
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsReturnWithCtx(ctx, os.Stdin)
	}

	return result, nil
}

// EnumerateMultipleDomainsAsLibrary wraps EnumerateMultipleDomainsAsLibraryWithCtx with an empty context
func (r *Runner) EnumerateMultipleDomainsReturn(reader io.Reader) (*MultipleEnumerationResult, error) {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleDomainsReturnWithCtx(ctx, reader)
}

// EnumerateMultipleDomainsAsLibraryWithCtx enumerates subdomains for multiple domains and returns structured results
func (r *Runner) EnumerateMultipleDomainsReturnWithCtx(ctx context.Context, reader io.Reader) (*MultipleEnumerationResult, error) {
	result := &MultipleEnumerationResult{
		Results: []EnumerationResult{},
		Errors:  []error{},
	}

	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)

	for scanner.Scan() {
		domain := preprocessDomain(scanner.Text())
		domain = replacer.Replace(domain)

		if domain == "" || (r.options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		enumResult, err := r.EnumerateSingleDomainReturnWithCtx(ctx, domain)
		if err != nil {
			result.Errors = append(result.Errors, err)
			continue
		}

		result.Results = append(result.Results, *enumResult)
	}

	return result, nil
}

// EnumerateSingleDomainAsLibrary wraps EnumerateSingleDomainAsLibraryWithCtx with an empty context
func (r *Runner) EnumerateSingleDomainAsLibrary(domain string) (*EnumerationResult, error) {
	return r.EnumerateSingleDomainReturnWithCtx(context.Background(), domain)
}

// EnumerateSingleDomainAsLibraryWithCtx performs subdomain enumeration against a single domain and returns structured results
func (r *Runner) EnumerateSingleDomainReturnWithCtx(ctx context.Context, domain string) (*EnumerationResult, error) {
	gologger.Info().Msgf("Enumerating subdomains for %s\n", domain)

	// Check if the user has asked to remove wildcards explicitly.
	// If yes, create the resolution pool and get the wildcards for the current domain
	var resolutionPool *resolve.ResolutionPool
	if r.options.RemoveWildcard {
		resolutionPool = r.resolverClient.NewResolutionPool(r.options.Threads, r.options.RemoveWildcard)
		err := resolutionPool.InitWildcards(domain)
		if err != nil {
			// Log the error but don't quit.
			gologger.Warning().Msgf("Could not get wildcards for domain %s: %s\n", domain, err)
		}
	}

	// Run the passive subdomain enumeration
	now := time.Now()
	passiveResults := r.passiveAgent.EnumerateSubdomainsWithCtx(ctx, domain, r.options.Proxy, r.options.RateLimit, r.options.Timeout, time.Duration(r.options.MaxEnumerationTime)*time.Minute, passive.WithCustomRateLimit(r.rateLimit))

	wg := &sync.WaitGroup{}
	wg.Add(1)
	// Create a unique map for filtering duplicate subdomains out
	uniqueMap := make(map[string]resolve.HostEntry)
	// Create a map to track sources for each host
	sourceMap := make(map[string]map[string]struct{})
	skippedCounts := make(map[string]int)
	// Process the results in a separate goroutine
	go func() {
		for result := range passiveResults {
			switch result.Type {
			case subscraping.Error:
				gologger.Warning().Msgf("Encountered an error with source %s: %s\n", result.Source, result.Error)
			case subscraping.Subdomain:
				subdomain := replacer.Replace(result.Value)

				// Validate the subdomain found and remove wildcards from
				if !strings.HasSuffix(subdomain, "."+domain) {
					skippedCounts[result.Source]++
					continue
				}

				if matchSubdomain := r.filterAndMatchSubdomain(subdomain); matchSubdomain {
					if _, ok := uniqueMap[subdomain]; !ok {
						sourceMap[subdomain] = make(map[string]struct{})
					}

					// Log the verbose message about the found subdomain per source
					if _, ok := sourceMap[subdomain][result.Source]; !ok {
						gologger.Verbose().Label(result.Source).Msg(subdomain)
					}

					sourceMap[subdomain][result.Source] = struct{}{}

					// Check if the subdomain is a duplicate. If not,
					// send the subdomain for resolution.
					if _, ok := uniqueMap[subdomain]; ok {
						skippedCounts[result.Source]++
						continue
					}

					hostEntry := resolve.HostEntry{Domain: domain, Host: subdomain, Source: result.Source}

					uniqueMap[subdomain] = hostEntry
					// If the user asked to remove wildcard then send on the resolve
					// queue. Otherwise, if mode is not verbose print the results on
					// the screen as they are discovered.
					if r.options.RemoveWildcard {
						resolutionPool.Tasks <- hostEntry
					}
				}
			}
		}
		// Close the task channel only if wildcards are asked to be removed
		if r.options.RemoveWildcard {
			close(resolutionPool.Tasks)
		}
		wg.Done()
	}()

	// If the user asked to remove wildcards, listen from the results
	// queue and write to the map. At the end, print the found results to the screen
	foundResults := make(map[string]resolve.Result)
	if r.options.RemoveWildcard {
		// Process the results coming from the resolutions pool
		for result := range resolutionPool.Results {
			switch result.Type {
			case resolve.Error:
				gologger.Warning().Msgf("Could not resolve host: %s\n", result.Error)
			case resolve.Subdomain:
				// Add the found subdomain to a map.
				if _, ok := foundResults[result.Host]; !ok {
					foundResults[result.Host] = result
				}
			}
		}
	}
	wg.Wait()

	// Show found subdomain count in any case.
	duration := durafmt.Parse(time.Since(now)).LimitFirstN(maxNumCount).String()
	var numberOfSubDomains int
	var hostEntries []resolve.HostEntry
	var subdomains []string

	if r.options.RemoveWildcard {
		numberOfSubDomains = len(foundResults)
		for _, result := range foundResults {
			hostEntries = append(hostEntries, resolve.HostEntry{Domain: domain, Host: result.Host, Source: result.Source})
			subdomains = append(subdomains, result.Host)
		}
	} else {
		numberOfSubDomains = len(uniqueMap)
		for _, v := range uniqueMap {
			hostEntries = append(hostEntries, v)
			subdomains = append(subdomains, v.Host)
		}
	}

	// Call result callback if provided
	if r.options.ResultCallback != nil {
		if r.options.RemoveWildcard {
			for _, result := range foundResults {
				r.options.ResultCallback(&resolve.HostEntry{Domain: domain, Host: result.Host, Source: result.Source})
			}
		} else {
			for _, v := range uniqueMap {
				r.options.ResultCallback(&v)
			}
		}
	}

	gologger.Info().Msgf("Found %d subdomains for %s in %s\n", numberOfSubDomains, domain, duration)

	// Prepare statistics if requested
	var statistics map[string]subscraping.Statistics
	if r.options.Statistics {
		gologger.Info().Msgf("Printing source statistics for %s", domain)
		statistics = r.passiveAgent.GetStatistics()
		// This is a hack to remove the skipped count from the statistics
		// as we don't want to show it in the statistics.
		// TODO: Design a better way to do this.
		for source, count := range skippedCounts {
			if stat, ok := statistics[source]; ok {
				stat.Results -= count
				statistics[source] = stat
			}
		}
		printStatistics(statistics)
	}

	return &EnumerationResult{
		Domain:      domain,
		Subdomains:  subdomains,
		HostEntries: hostEntries,
		SourceMap:   sourceMap,
		Statistics:  statistics,
		Duration:    duration,
	}, nil
}

// EnumerateMultipleDomains wraps EnumerateMultipleDomainsWithCtx with an empty context
func (r *Runner) EnumerateMultipleDomains(reader io.Reader, writers []io.Writer) error {
	ctx, _ := contextutil.WithValues(context.Background(), contextutil.ContextArg("All"), contextutil.ContextArg(strconv.FormatBool(r.options.All)))
	return r.EnumerateMultipleDomainsWithCtx(ctx, reader, writers)
}

// EnumerateMultipleDomainsWithCtx enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	var err error
	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain := preprocessDomain(scanner.Text())
		domain = replacer.Replace(domain)

		if domain == "" || (r.options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each domain. Else create a new file
		// for each domain in the directory.
		if r.options.OutputFile != "" {
			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			if closeErr := file.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", r.options.OutputFile, closeErr)
			}
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, domain)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			if closeErr := file.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", outputFile, closeErr)
			}
		} else {
			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, writers)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
