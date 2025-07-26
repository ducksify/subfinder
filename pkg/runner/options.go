package runner

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/ducksify/subfinder/v2/pkg/passive"
	"github.com/ducksify/subfinder/v2/pkg/resolve"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	logutil "github.com/projectdiscovery/utils/log"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	configDir                     = folderutil.AppConfigDirOrDefault(".", "subfinder")
	defaultConfigLocation         = filepath.Join(configDir, "config.yaml")
	defaultProviderConfigLocation = filepath.Join(configDir, "provider-config.yaml")
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool                // Verbose flag indicates whether to show verbose output or not
	NoColor            bool                // NoColor disables the colored output
	JSON               bool                // JSON specifies whether to use json for output format or text file
	HostIP             bool                // HostIP specifies whether to write subdomains in host:ip format
	Silent             bool                // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool                // ListSources specifies whether to list all available sources
	RemoveWildcard     bool                // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources     bool                // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin              bool                // Stdin specifies whether stdin input was given to the process
	Version            bool                // Version specifies if we should just show version and exit
	OnlyRecursive      bool                // Recursive specifies whether to use only recursive subdomain enumeration sources
	All                bool                // All specifies whether to use all (slow) sources.
	Statistics         bool                // Statistics specifies whether to report source statistics
	Threads            int                 // Threads controls the number of threads to use for active enumerations
	Timeout            int                 // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                 // MaxEnumerationTime is the maximum amount of time in minutes to wait for enumeration
	Domain             goflags.StringSlice // Domain is the domain to find subdomains for
	DomainsFile        string              // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string               // Output is the file to write found subdomains to.
	OutputDirectory    string               // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            goflags.StringSlice  `yaml:"sources,omitempty"`         // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     goflags.StringSlice  `yaml:"exclude-sources,omitempty"` // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	Resolvers          goflags.StringSlice  `yaml:"resolvers,omitempty"`       // Resolvers is the comma-separated resolvers to use for enumeration
	ResolverList       string               // ResolverList is a text file containing list of resolvers to use for enumeration
	Config             string               // Config contains the location of the config file
	ProviderConfig     string               // ProviderConfig contains the location of the provider config file
	Proxy              string               // HTTP proxy
	RateLimit          int                  // Global maximum number of HTTP requests to send per second
	RateLimits         goflags.RateLimitMap // Maximum number of HTTP requests to send per second
	ExcludeIps         bool
	Match              goflags.StringSlice
	Filter             goflags.StringSlice
	matchRegexes       []*regexp.Regexp
	filterRegexes      []*regexp.Regexp
	ResultCallback     OnResultCallback // OnResult callback
	DisableUpdateCheck bool             // DisableUpdateCheck disable update checking
}

// OnResultCallback (hostResult)
type OnResultCallback func(result *resolve.HostEntry)

// ParseOptions parses the command line flags provided by a user
func ParseOptions(options *Options) *Options {
	logutil.DisableDefaultLogger()


	// set chaos mode
	chaos.IsSDK = false

	if exists := fileutil.FileExists(defaultProviderConfigLocation); !exists {
		if err := createProviderConfigYAML(defaultProviderConfigLocation); err != nil {
			gologger.Error().Msgf("Could not create provider config file: %s\n", err)
		}
	}

	var err error
	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = fileutil.HasStdin()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		gologger.Info().Msgf("Subfinder Config Directory: %s", configDir)
		os.Exit(0)
	}

	options.preProcessDomains()

	options.ConfigureOutput()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("subfinder", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("subfinder version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current subfinder version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// loadProvidersFrom runs the app with source config
func (options *Options) loadProvidersFrom(location string) {
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Resolvers = resolve.DefaultResolvers
	}

	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := UnmarshalFrom(location); err != nil && (!strings.Contains(err.Error(), "file doesn't exist") || errors.Is(err, os.ErrNotExist)) {
		gologger.Error().Msgf("Could not read providers from %s: %s\n", location, err)
	}
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(passive.AllSources))
	gologger.Info().Msgf("Sources marked with an * need key(s) or token(s) to work.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys/tokens.\n\n", options.ProviderConfig)

	for _, source := range passive.AllSources {
		message := "%s\n"
		sourceName := source.Name()
		if source.NeedsKey() {
			message = "%s *\n"
		}
		gologger.Silent().Msgf(message, sourceName)
	}
}

func (options *Options) preProcessDomains() {
	for i, domain := range options.Domain {
		options.Domain[i] = preprocessDomain(domain)
	}
}

var defaultRateLimits = []string{
	"github=30/m",
	"fullhunt=60/m",
	"pugrecon=10/s",
	fmt.Sprintf("robtex=%d/ms", uint(math.MaxUint)),
	"securitytrails=1/s",
	"shodan=1/s",
	"virustotal=4/m",
	"hackertarget=2/s",
	// "threatminer=10/m",
	"waybackarchive=15/m",
	"whoisxmlapi=50/s",
	"securitytrails=2/s",
	"sitedossier=8/m",
	"netlas=1/s",
	// "gitlab=2/s",
	"github=83/m",
	"hudsonrock=5/s",
}
