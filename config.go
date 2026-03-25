package zgrab2

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	//"golang.org/x/time/rate"

	"github.com/censys/cidranger"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	IPVersionCapabilityTimeout     = 10 * time.Second
	IPVersionCapabilityIPv4Address = "1.1.1.1:80"              // Cloudflare has this IP/Port redirect to https://one.one.one.one. We can use it to test if this host has IPv4 connectivity
	IPVersionCapabilityIPv6Address = "2606:4700:4700::1111:80" // Same as above for IPv6
)

var prometheusOnce sync.Once // Used to ensure we only start the Prometheus server once, even if ValidateAndHandleFrameworkConfiguration is called multiple times
const (
	defaultSenders          = 1_000
	defaultGOMAXPROCS       = 0
	defaultReadLimitPerHost = 96

	defaultFileName = "-"

	defaultConnectionsPerHost   = 1
	defaultDNSServerRateLimit   = 10_000
	defaultDNSResolutionTimeout = 10 * time.Second
	defaultServerRateLimit      = 20
)

type GeneralOptions struct {
	Senders          int    `short:"s" long:"senders" description:"Number of send goroutines to use"`
	GOMAXPROCS       int    `long:"gomaxprocs" description:"Set GOMAXPROCS to set the number of CPU cores to use. 0 uses all available. (default: 0)"`
	Prometheus       string `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	ReadLimitPerHost int    `long:"read-limit-per-host" description:"Maximum total kilobytes to read for a single host"`
}

type InputOutputOptions struct {
	BlocklistFileName     string `short:"b" long:"blocklist-file" description:"Blocklist filename, use - for $(HOME)/.config/zgrab2/blocklist.conf."`
	InputFileName         string `short:"f" long:"input-file" description:"Input filename, use - for stdin."`
	LogFileName           string `short:"l" long:"log-file" description:"Log filename, use - for stderr."`
	MetaFileName          string `short:"m" long:"metadata-file" description:"Metadata filename, use - for stderr."`
	OutputFileName        string `short:"o" long:"output-file" description:"Output filename, use - for stdout."`
	StatusUpdatesFileName string `short:"u" long:"status-updates-file" description:"Status updates filename, use - for stderr."`
	Debug                 bool   `long:"debug" description:"Include debug fields in the output."`
	Flush                 bool   `long:"flush" description:"Flush after each line of output."`
}

type NetworkingOptions struct {
	ConnectionsPerHost   int           `long:"connections-per-host" description:"Number of times to connect to each host (results in more output)"`
	DNSServerRateLimit   int           `long:"dns-rate-limit"  description:"Rate limit for DNS lookups per second."`
	DNSResolutionTimeout time.Duration `long:"dns-resolution-timeout" description:"Timeout for DNS resolution of target hostnames."`
	CustomDNS            string        `long:"dns-resolvers" description:"Address of a custom DNS server(s) for lookups, comma-delimited. Default port is 53. Ex: 1.1.1.1:53,8.8.8.8. Uses the OS-default resolvers if not set."`
	LocalAddrString      string        `long:"local-addr" description:"Local address(es) to bind to for outgoing connections. Comma-separated list of IP addresses, ranges (inclusive), or CIDR blocks, ex: 1.1.1.1-1.1.1.3, 2.2.2.2, 3.3.3.0/24"`
	LocalPortString      string        `long:"local-port" description:"Local port(s) to bind to for outgoing connections. Comma-separated list of ports or port ranges (inclusive) ex: 1200-1300,2000"`
	UserIPv4Choice       *bool         `long:"resolve-ipv4" description:"Use IPv4 for resolving domains (accept A records). True by default, use only --resolve-ipv6 for IPv6 only resolution. If used with --resolve-ipv6, will use both IPv4 and IPv6."`
	UserIPv6Choice       *bool         `long:"resolve-ipv6" description:"Use IPv6 for resolving domains (accept AAAA records). IPv6 is disabled by default. If --resolve-ipv4 is not set and --resolve-ipv6 is, will only use IPv6. If used with --resolve-ipv4, will use both IPv4 and IPv6."`
	ServerRateLimit      int           `long:"server-rate-limit" description:"Per-IP rate limit for connections to targets per second."`
}

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	GeneralOptions                       // CLI Options related to general framework configuration. Don't fit into any other category
	InputOutputOptions                   // CLI Options related to I/O. Just affects organization of --help
	NetworkingOptions                    // CLI Options related to networking. Just affects organization of --help
	Multiple             MultipleCommand `command:"multiple" description:"Multiple module actions"`
	inputFile            *os.File
	outputFile           *os.File
	metaFile             *os.File
	statusUpdatesFile    *os.File
	logFile              *os.File
	inputTargets         InputTargetsFunc
	outputResults        OutputResultsFunc
	customDNSNameservers []string // will be non-empty if user specified custom DNS, we'll check these are reachable before populating
	localAddrs           []net.IP // will be non-empty if user specified local addresses
	localPorts           []uint16 // will be non-empty if user specified local ports
	resolveIPv4          bool     // true if IPv4 is enabled, false if only IPv6 is enabled. Guaranteed to be set, whereas UserIPv4Choice may be nil if unset by the user
	resolveIPv6          bool
	WeakCSList           map[string][]uint16
}

// SetInputFunc sets the target input function to the provided function.
func SetInputFunc(f InputTargetsFunc) {
	config.inputTargets = f
}

// SetOutputFunc sets the result output function to the provided function.
func SetOutputFunc(f OutputResultsFunc) {
	config.outputResults = f
}

func init() {
	config = Config{
		GeneralOptions: GeneralOptions{
			Senders:          defaultSenders,
			GOMAXPROCS:       defaultGOMAXPROCS,
			ReadLimitPerHost: defaultReadLimitPerHost,
		},
		InputOutputOptions: InputOutputOptions{
			BlocklistFileName:     defaultFileName,
			InputFileName:         defaultFileName,
			LogFileName:           defaultFileName,
			MetaFileName:          defaultFileName,
			OutputFileName:        defaultFileName,
			StatusUpdatesFileName: defaultFileName,
		},
		NetworkingOptions: NetworkingOptions{
			ConnectionsPerHost:   defaultConnectionsPerHost,
			DNSServerRateLimit:   defaultDNSServerRateLimit,
			DNSResolutionTimeout: defaultDNSResolutionTimeout,
			ServerRateLimit:      defaultServerRateLimit,
		},
	}
	config.Multiple.ContinueOnError = true // set default for multiple value
	config.Multiple.BreakOnSuccess = false // set default for multiple value
}

func GetWeakCSFromProtoVersion(protoVersion string) []uint16 {
	csList, ok := config.WeakCSList[protoVersion]
	if !ok {
		return nil
	}
	return csList
}

var config Config
var blocklist cidranger.Ranger

// ValidateAndHandleFrameworkConfiguration configures and validates the ZGrab2 config struct, e.g. taking the --input-file string
// and opening the file, or starting the Prometheus server, if configured.
// It is safe to call this function multiple times (and this occurs when using the --multiple command: 1) for parsing the
// command line flags, and 2) for parsing the INI file). Actions which should only be done once, such as starting the
// Prometheus server, are guarded by a sync.Once variable.
func ValidateAndHandleFrameworkConfiguration() {
	// validate files
	if config.LogFileName == "-" {
		config.logFile = os.Stderr
	} else {
		var err error
		if config.logFile, err = os.Create(config.LogFileName); err != nil {
			log.Fatal(err)
		}
		log.SetOutput(config.logFile)
	}
	SetInputFunc(InputTargetsCSV)

	if config.InputFileName == "-" {
		config.inputFile = os.Stdin
	} else {
		var err error
		if config.inputFile, err = os.Open(config.InputFileName); err != nil {
			log.Fatal(err)
		}
	}

	if config.OutputFileName == "-" {
		config.outputFile = os.Stdout
	} else {
		var err error
		if config.outputFile, err = os.Create(config.OutputFileName); err != nil {
			log.Fatal(err)
		}
	}
	outputFunc := OutputResultsWriterFunc(config.outputFile)
	SetOutputFunc(outputFunc)

	if config.MetaFileName == "-" {
		config.metaFile = os.Stderr
	} else if len(config.MetaFileName) > 0 {
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(fmt.Errorf("error creating meta file: %w", err))
		}
	}

	if config.StatusUpdatesFileName == "-" {
		config.statusUpdatesFile = os.Stderr
	} else if len(config.StatusUpdatesFileName) > 0 {
		var err error
		if config.statusUpdatesFile, err = os.Create(config.StatusUpdatesFileName); err != nil {
			log.Fatal(fmt.Errorf("error creating status updates file: %w", err))
		}
	}

	// Validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatalf("invalid GOMAXPROCS (must be positive, given %d)", config.GOMAXPROCS)
	}
	runtime.GOMAXPROCS(config.GOMAXPROCS)

	//validate/start prometheus
	if config.Prometheus != "" {
		go func() {
			prometheusOnce.Do(func() {
				http.Handle("/metrics", promhttp.Handler())
				if err := http.ListenAndServe(config.Prometheus, nil); err != nil {
					log.Fatalf("could not run prometheus server: %s", err.Error())
				}
			})
		}()
	}

	//validate senders
	if config.Senders <= 0 {
		log.Fatalf("need at least one sender, given %d", config.Senders)
	}

	// validate connections per host
	if config.ConnectionsPerHost <= 0 {
		log.Fatalf("need at least one connection, given %d", config.ConnectionsPerHost)
	}

	// Stop the lowliest idiot from using this to DoS people
	if config.ConnectionsPerHost > 50 {
		log.Fatalf("connectionsPerHost must be in the range [0,50]")
	}

	// Stop even third-party libraries from performing unbounded reads on untrusted hosts
	if config.ReadLimitPerHost > 0 {
		DefaultBytesReadLimit = config.ReadLimitPerHost * 1024
	}

	// If user specifies nothing, default to IPv4
	// If only --use-ipv6 is set, => IPv6
	// if only --use-ipv4 is set, => IPv4
	// if both are set, => both IPv4 and IPv6
	// Cannot use neither IPv4 nor IPv6, for obvious reasons
	userSpecifiedUseIPv4 := config.UserIPv4Choice != nil && *config.UserIPv4Choice
	userSpecifiedUseIPv6 := config.UserIPv6Choice != nil && *config.UserIPv6Choice
	if !userSpecifiedUseIPv4 && !userSpecifiedUseIPv6 {
		// If both are unset, default to using IPv4
		config.resolveIPv4 = true
		config.resolveIPv6 = false
	} else if userSpecifiedUseIPv4 && !userSpecifiedUseIPv6 {
		// If only IPv4 is set, use IPv4
		config.resolveIPv4 = true
		config.resolveIPv6 = false
	} else if !userSpecifiedUseIPv4 && userSpecifiedUseIPv6 {
		// If only IPv6 is set, use IPv6
		config.resolveIPv4 = false
		config.resolveIPv6 = true
	} else {
		// If both are set, use both IPv4 and IPv6
		config.resolveIPv4 = true
		config.resolveIPv6 = true
	}

	// If localAddrString is set, parse it into a list of IP addresses to use for source IPs
	if config.LocalAddrString != "" {
		ips, err := extractIPAddresses(strings.Split(config.LocalAddrString, ","))
		if err != nil {
			log.Fatalf("could not extract IP addresses from address string %s: %s", config.LocalAddrString, err)
		}
		for _, ip := range ips {
			if ip == nil {
				log.Fatalf("could not extract IP addresses from address string: %s", config.LocalAddrString)
			}
		}
		config.localAddrs = ips
	}

	if !config.resolveIPv4 && !config.resolveIPv6 {
		log.Fatalf("must use either IPv4 or IPv6, or both. Use --use-ipv4 and/or --use-ipv6 to enable them.")
	}

	// Validate custom DNS must occur after setting resolveIPv4 and resolveIPv6
	if config.CustomDNS != "" {
		var err error
		if config.customDNSNameservers, err = parseCustomDNSString(config.CustomDNS); err != nil {
			log.Fatalf("invalid DNS server address: %s", err)
		}
	}

	config.WeakCSList = map[string][]uint16{
		"SSLv3": {
			0x0000,
			0x0001, // SSL_RSA_WITH_NULL_MD5
			0x0002, // SSL_RSA_WITH_NULL_SHA
			0x0004, // SSL_RSA_WITH_RC4_128_MD5
			0x0005, // SSL_RSA_WITH_RC4_128_SHA
			0x0007, // SSL_RSA_WITH_IDEA_CBC_SHA
			0x0008, // SSL_RSA_WITH_DES_CBC_SHA
			0x0009, // SSL_RSA_WITH_3DES_EDE_CBC_SHA
			0x002f, // SSL_RSA_WITH_AES_128_CBC_SHA
			0x0035, // SSL_RSA_WITH_AES_256_CBC_SHA
			0x003c, // SSL_DHE_RSA_WITH_AES_128_CBC_SHA
			0x003d, // SSL_DHE_RSA_WITH_AES_256_CBC_SHA
			0x000a, // SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
		},
		"TLSv1.0": {
			0xd,    // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
			0x30,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA
			0x36,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA
			0xc03e, // TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
			0xc03f, // TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
			0x42,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbb,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0x85,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc1,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0x97,   // TLS_DH_DSS_WITH_SEED_CBC_SHA
			0x13,   // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
			0x32,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			0x38,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0xc042, // TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
			0xc043, // TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
			0x44,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbd,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0x87,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc3,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0x99,   // TLS_DHE_DSS_WITH_SEED_CBC_SHA
			0x8f,   // TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
			0x90,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA
			0xb2,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
			0x91,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA
			0xb3,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
			0xc066, // TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc067, // TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc096, // TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc097, // TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0x16,   // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
			0x33,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x39,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0xc044, // TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc045, // TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
			0x45,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbe,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x88,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc4,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x9a,   // TLS_DHE_RSA_WITH_SEED_CBC_SHA
			0x10,   // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
			0x31,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA
			0x37,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA
			0xc040, // TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc041, // TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
			0x43,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbc,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x86,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc2,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x98,   // TLS_DH_RSA_WITH_SEED_CBC_SHA
			0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc004, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
			0xc005, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
			0xc04a, // TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc04b, // TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc048, // TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc049, // TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc034, // TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
			0xc035, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
			0xc037, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
			0xc036, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
			0xc038, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
			0xc070, // TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc071, // TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc09a, // TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc09b, // TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc04c, // TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04d, // TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
			0xc00e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
			0xc00f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
			0xc04e, // TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04f, // TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
			0x1f,   // TLS_KRB5_WITH_3DES_EDE_CBC_SHA
			0x21,   // TLS_KRB5_WITH_IDEA_CBC_SHA
			0x8b,   // TLS_PSK_WITH_3DES_EDE_CBC_SHA
			0x8c,   // TLS_PSK_WITH_AES_128_CBC_SHA
			0xae,   // TLS_PSK_WITH_AES_128_CBC_SHA256
			0x8d,   // TLS_PSK_WITH_AES_256_CBC_SHA
			0xaf,   // TLS_PSK_WITH_AES_256_CBC_SHA384
			0xc064, // TLS_PSK_WITH_ARIA_128_CBC_SHA256
			0xc065, // TLS_PSK_WITH_ARIA_256_CBC_SHA384
			0xc094, // TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc095, // TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0x93,   // TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
			0x94,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA
			0xb6,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
			0x95,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA
			0xb7,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
			0xc068, // TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
			0xc069, // TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
			0xc098, // TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc099, // TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xa,    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			0x2f,   // TLS_RSA_WITH_AES_128_CBC_SHA
			0x35,   // TLS_RSA_WITH_AES_256_CBC_SHA
			0xc03c, // TLS_RSA_WITH_ARIA_128_CBC_SHA256
			0xc03d, // TLS_RSA_WITH_ARIA_256_CBC_SHA384
			0x41,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xba,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x84,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc0,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x7,    // TLS_RSA_WITH_IDEA_CBC_SHA
			0x96,   // TLS_RSA_WITH_SEED_CBC_SHA
			0xc01c, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
			0xc01f, // TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
			0xc022, // TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
			0xc01b, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
			0xc01e, // TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
			0xc021, // TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
			0xc01a, // TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
			0xc01d, // TLS_SRP_SHA_WITH_AES_128_CBC_SHA
			0xc020, // TLS_SRP_SHA_WITH_AES_256_CBC_SHA
			0x19,   // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
			0x17,   // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
			0x1b,   // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
			0x34,   // TLS_DH_anon_WITH_AES_128_CBC_SHA
			0x3a,   // TLS_DH_anon_WITH_AES_256_CBC_SHA
			0xc046, // TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
			0xc047, // TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
			0x46,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
			0xbf,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
			0x89,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
			0xc5,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
			0x1a,   // TLS_DH_anon_WITH_DES_CBC_SHA
			0x18,   // TLS_DH_anon_WITH_RC4_128_MD5
			0x9b,   // TLS_DH_anon_WITH_SEED_CBC_SHA
			0xb,    // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
			0xc,    // TLS_DH_DSS_WITH_DES_CBC_SHA
			0x11,   // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
			0x12,   // TLS_DHE_DSS_WITH_DES_CBC_SHA
			0x2d,   // TLS_DHE_PSK_WITH_NULL_SHA
			0xb4,   // TLS_DHE_PSK_WITH_NULL_SHA256
			0xb5,   // TLS_DHE_PSK_WITH_NULL_SHA384
			0x8e,   // TLS_DHE_PSK_WITH_RC4_128_SHA
			0x14,   // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x15,   // TLS_DHE_RSA_WITH_DES_CBC_SHA
			0xe,    // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
			0xf,    // TLS_DH_RSA_WITH_DES_CBC_SHA
			0xc017, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
			0xc018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
			0xc019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
			0xc015, // TLS_ECDH_anon_WITH_NULL_SHA
			0xc016, // TLS_ECDH_anon_WITH_RC4_128_SHA
			0xc001, // TLS_ECDH_ECDSA_WITH_NULL_SHA
			0xc002, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
			0xc006, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
			0xc007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
			0xc039, // TLS_ECDHE_PSK_WITH_NULL_SHA
			0xc03a, // TLS_ECDHE_PSK_WITH_NULL_SHA256
			0xc03b, // TLS_ECDHE_PSK_WITH_NULL_SHA384
			0xc033, // TLS_ECDHE_PSK_WITH_RC4_128_SHA
			0xc010, // TLS_ECDHE_RSA_WITH_NULL_SHA
			0xc011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
			0xc00b, // TLS_ECDH_RSA_WITH_NULL_SHA
			0xc00c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
			0xc102, // TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
			0xc100, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
			0xc101, // TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
			0x29,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
			0x26,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
			0x2a,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
			0x27,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
			0x2b,   // TLS_KRB5_EXPORT_WITH_RC4_40_MD5
			0x28,   // TLS_KRB5_EXPORT_WITH_RC4_40_SHA
			0x23,   // TLS_KRB5_WITH_3DES_EDE_CBC_MD5
			0x22,   // TLS_KRB5_WITH_DES_CBC_MD5
			0x1e,   // TLS_KRB5_WITH_DES_CBC_SHA
			0x25,   // TLS_KRB5_WITH_IDEA_CBC_MD5
			0x24,   // TLS_KRB5_WITH_RC4_128_MD5
			0x20,   // TLS_KRB5_WITH_RC4_128_SHA
			0x0,    // TLS_NULL_WITH_NULL_NULL
			0x2c,   // TLS_PSK_WITH_NULL_SHA
			0xb0,   // TLS_PSK_WITH_NULL_SHA256
			0xb1,   // TLS_PSK_WITH_NULL_SHA384
			0x8a,   // TLS_PSK_WITH_RC4_128_SHA
			0x8,    // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x6,    // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
			0x3,    // TLS_RSA_EXPORT_WITH_RC4_40_MD5
			0x2e,   // TLS_RSA_PSK_WITH_NULL_SHA
			0xb8,   // TLS_RSA_PSK_WITH_NULL_SHA256
			0xb9,   // TLS_RSA_PSK_WITH_NULL_SHA384
			0x92,   // TLS_RSA_PSK_WITH_RC4_128_SHA
			0x9,    // TLS_RSA_WITH_DES_CBC_SHA
			0x1,    // TLS_RSA_WITH_NULL_MD5
			0x2,    // TLS_RSA_WITH_NULL_SHA
			0x4,    // TLS_RSA_WITH_RC4_128_MD5
			0x5,    // TLS_RSA_WITH_RC4_128_SHA
		},
		"TLSv1.1": {
			0xd,    // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
			0x30,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA
			0x36,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA
			0xc03e, // TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
			0xc03f, // TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
			0x42,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbb,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0x85,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc1,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0x97,   // TLS_DH_DSS_WITH_SEED_CBC_SHA
			0x13,   // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
			0x32,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			0x38,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0xc042, // TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
			0xc043, // TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
			0x44,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbd,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0x87,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc3,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0x99,   // TLS_DHE_DSS_WITH_SEED_CBC_SHA
			0x8f,   // TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
			0x90,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA
			0xb2,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
			0x91,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA
			0xb3,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
			0xc066, // TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc067, // TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc096, // TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc097, // TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0x16,   // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
			0x33,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x39,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0xc044, // TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc045, // TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
			0x45,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbe,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x88,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc4,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x9a,   // TLS_DHE_RSA_WITH_SEED_CBC_SHA
			0x10,   // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
			0x31,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA
			0x37,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA
			0xc040, // TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc041, // TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
			0x43,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbc,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x86,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc2,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x98,   // TLS_DH_RSA_WITH_SEED_CBC_SHA
			0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc004, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
			0xc005, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
			0xc04a, // TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc04b, // TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc048, // TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc049, // TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc034, // TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
			0xc035, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
			0xc037, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
			0xc036, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
			0xc038, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
			0xc070, // TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc071, // TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc09a, // TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc09b, // TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc04c, // TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04d, // TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
			0xc00e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
			0xc00f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
			0xc04e, // TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04f, // TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
			0x1f,   // TLS_KRB5_WITH_3DES_EDE_CBC_SHA
			0x21,   // TLS_KRB5_WITH_IDEA_CBC_SHA
			0x8b,   // TLS_PSK_WITH_3DES_EDE_CBC_SHA
			0x8c,   // TLS_PSK_WITH_AES_128_CBC_SHA
			0xae,   // TLS_PSK_WITH_AES_128_CBC_SHA256
			0x8d,   // TLS_PSK_WITH_AES_256_CBC_SHA
			0xaf,   // TLS_PSK_WITH_AES_256_CBC_SHA384
			0xc064, // TLS_PSK_WITH_ARIA_128_CBC_SHA256
			0xc065, // TLS_PSK_WITH_ARIA_256_CBC_SHA384
			0xc094, // TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc095, // TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0x93,   // TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
			0x94,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA
			0xb6,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
			0x95,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA
			0xb7,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
			0xc068, // TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
			0xc069, // TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
			0xc098, // TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc099, // TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xa,    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			0x2f,   // TLS_RSA_WITH_AES_128_CBC_SHA
			0x35,   // TLS_RSA_WITH_AES_256_CBC_SHA
			0xc03c, // TLS_RSA_WITH_ARIA_128_CBC_SHA256
			0xc03d, // TLS_RSA_WITH_ARIA_256_CBC_SHA384
			0x41,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xba,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0x84,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc0,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0x7,    // TLS_RSA_WITH_IDEA_CBC_SHA
			0x96,   // TLS_RSA_WITH_SEED_CBC_SHA
			0xc01c, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
			0xc01f, // TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
			0xc022, // TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
			0xc01b, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
			0xc01e, // TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
			0xc021, // TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
			0xc01a, // TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
			0xc01d, // TLS_SRP_SHA_WITH_AES_128_CBC_SHA
			0xc020, // TLS_SRP_SHA_WITH_AES_256_CBC_SHA
			0x19,   // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
			0x17,   // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
			0x1b,   // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
			0x34,   // TLS_DH_anon_WITH_AES_128_CBC_SHA
			0x3a,   // TLS_DH_anon_WITH_AES_256_CBC_SHA
			0xc046, // TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
			0xc047, // TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
			0x46,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
			0xbf,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
			0x89,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
			0xc5,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
			0x1a,   // TLS_DH_anon_WITH_DES_CBC_SHA
			0x18,   // TLS_DH_anon_WITH_RC4_128_MD5
			0x9b,   // TLS_DH_anon_WITH_SEED_CBC_SHA
			0xb,    // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
			0xc,    // TLS_DH_DSS_WITH_DES_CBC_SHA
			0x11,   // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
			0x12,   // TLS_DHE_DSS_WITH_DES_CBC_SHA
			0x2d,   // TLS_DHE_PSK_WITH_NULL_SHA
			0xb4,   // TLS_DHE_PSK_WITH_NULL_SHA256
			0xb5,   // TLS_DHE_PSK_WITH_NULL_SHA384
			0x8e,   // TLS_DHE_PSK_WITH_RC4_128_SHA
			0x14,   // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x15,   // TLS_DHE_RSA_WITH_DES_CBC_SHA
			0xe,    // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
			0xf,    // TLS_DH_RSA_WITH_DES_CBC_SHA
			0xc017, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
			0xc018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
			0xc019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
			0xc015, // TLS_ECDH_anon_WITH_NULL_SHA
			0xc016, // TLS_ECDH_anon_WITH_RC4_128_SHA
			0xc001, // TLS_ECDH_ECDSA_WITH_NULL_SHA
			0xc002, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
			0xc006, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
			0xc007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
			0xc039, // TLS_ECDHE_PSK_WITH_NULL_SHA
			0xc03a, // TLS_ECDHE_PSK_WITH_NULL_SHA256
			0xc03b, // TLS_ECDHE_PSK_WITH_NULL_SHA384
			0xc033, // TLS_ECDHE_PSK_WITH_RC4_128_SHA
			0xc010, // TLS_ECDHE_RSA_WITH_NULL_SHA
			0xc011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
			0xc00b, // TLS_ECDH_RSA_WITH_NULL_SHA
			0xc00c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
			0xc102, // TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
			0xc100, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
			0xc101, // TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
			0x29,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
			0x26,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
			0x2a,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
			0x27,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
			0x2b,   // TLS_KRB5_EXPORT_WITH_RC4_40_MD5
			0x28,   // TLS_KRB5_EXPORT_WITH_RC4_40_SHA
			0x23,   // TLS_KRB5_WITH_3DES_EDE_CBC_MD5
			0x22,   // TLS_KRB5_WITH_DES_CBC_MD5
			0x1e,   // TLS_KRB5_WITH_DES_CBC_SHA
			0x25,   // TLS_KRB5_WITH_IDEA_CBC_MD5
			0x24,   // TLS_KRB5_WITH_RC4_128_MD5
			0x20,   // TLS_KRB5_WITH_RC4_128_SHA
			0x0,    // TLS_NULL_WITH_NULL_NULL
			0x2c,   // TLS_PSK_WITH_NULL_SHA
			0xb0,   // TLS_PSK_WITH_NULL_SHA256
			0xb1,   // TLS_PSK_WITH_NULL_SHA384
			0x8a,   // TLS_PSK_WITH_RC4_128_SHA
			0x8,    // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x6,    // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
			0x3,    // TLS_RSA_EXPORT_WITH_RC4_40_MD5
			0x2e,   // TLS_RSA_PSK_WITH_NULL_SHA
			0xb8,   // TLS_RSA_PSK_WITH_NULL_SHA256
			0xb9,   // TLS_RSA_PSK_WITH_NULL_SHA384
			0x92,   // TLS_RSA_PSK_WITH_RC4_128_SHA
			0x9,    // TLS_RSA_WITH_DES_CBC_SHA
			0x1,    // TLS_RSA_WITH_NULL_MD5
			0x2,    // TLS_RSA_WITH_NULL_SHA
			0x4,    // TLS_RSA_WITH_RC4_128_MD5
			0x5,    // TLS_RSA_WITH_RC4_128_SHA
		},
		"TLSv1.2": {
			0xd,    // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
			0x30,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA
			0x3e,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA256
			0xa4,   // TLS_DH_DSS_WITH_AES_128_GCM_SHA256
			0x36,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA
			0x68,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA256
			0xa5,   // TLS_DH_DSS_WITH_AES_256_GCM_SHA384
			0xc03e, // TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
			0xc058, // TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256
			0xc03f, // TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
			0xc059, // TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384
			0x42,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbb,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0xc082, // TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
			0x85,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc1,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0xc083, // TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
			0x97,   // TLS_DH_DSS_WITH_SEED_CBC_SHA
			0x13,   // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
			0x32,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			0x40,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
			0xa2,   // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
			0x38,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0x6a,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
			0xa3,   // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
			0xc042, // TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
			0xc056, // TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
			0xc043, // TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
			0xc057, // TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
			0x44,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbd,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0xc080, // TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
			0x87,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc3,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0xc081, // TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
			0x99,   // TLS_DHE_DSS_WITH_SEED_CBC_SHA
			0x8f,   // TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
			0x90,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA
			0xb2,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
			0xc0a6, // TLS_DHE_PSK_WITH_AES_128_CCM
			0xaa,   // TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
			0x91,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA
			0xb3,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
			0xc0a7, // TLS_DHE_PSK_WITH_AES_256_CCM
			0xab,   // TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
			0xc066, // TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06c, // TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
			0xc067, // TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06d, // TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
			0xc096, // TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc090, // TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc097, // TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc091, // TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccad, // TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
			0x16,   // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
			0x33,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x67,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
			0xc09e, // TLS_DHE_RSA_WITH_AES_128_CCM
			0xc0a2, // TLS_DHE_RSA_WITH_AES_128_CCM_8
			0x9e,   // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
			0x39,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x6b,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
			0xc09f, // TLS_DHE_RSA_WITH_AES_256_CCM
			0xc0a3, // TLS_DHE_RSA_WITH_AES_256_CCM_8
			0x9f,   // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			0xc044, // TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc052, // TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xc045, // TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc053, // TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
			0x45,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbe,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07c, // TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x88,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc4,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07d, // TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0xccaa, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0x9a,   // TLS_DHE_RSA_WITH_SEED_CBC_SHA
			0x10,   // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
			0x31,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA
			0x3f,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA256
			0xa0,   // TLS_DH_RSA_WITH_AES_128_GCM_SHA256
			0x37,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA
			0x69,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA256
			0xa1,   // TLS_DH_RSA_WITH_AES_256_GCM_SHA384
			0xc040, // TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc054, // TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256
			0xc041, // TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
			0xc055, // TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384
			0x43,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbc,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07e, // TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x86,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc2,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07f, // TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x98,   // TLS_DH_RSA_WITH_SEED_CBC_SHA
			0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc004, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
			0xc025, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
			0xc02d, // TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
			0xc005, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
			0xc026, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
			0xc02e, // TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
			0xc04a, // TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc05e, // TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
			0xc04b, // TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc05f, // TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
			0xc074, // TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc088, // TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
			0xc075, // TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc089, // TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
			0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0xc048, // TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc049, // TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc072, // TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc073, // TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc034, // TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
			0xc035, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
			0xc037, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
			0xc036, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
			0xc038, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
			0xc070, // TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc071, // TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc09a, // TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc09b, // TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0xc04c, // TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04d, // TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc076, // TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc077, // TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
			0xc00e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
			0xc029, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
			0xc031, // TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
			0xc00f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
			0xc02a, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
			0xc032, // TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
			0xc04e, // TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc062, // TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
			0xc04f, // TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
			0xc063, // TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
			0xc078, // TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc08c, // TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0xc079, // TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc08d, // TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x1f,   // TLS_KRB5_WITH_3DES_EDE_CBC_SHA
			0x21,   // TLS_KRB5_WITH_IDEA_CBC_SHA
			0xc0aa, // TLS_PSK_DHE_WITH_AES_128_CCM_8
			0xc0ab, // TLS_PSK_DHE_WITH_AES_256_CCM_8
			0x8b,   // TLS_PSK_WITH_3DES_EDE_CBC_SHA
			0x8c,   // TLS_PSK_WITH_AES_128_CBC_SHA
			0xae,   // TLS_PSK_WITH_AES_128_CBC_SHA256
			0xc0a4, // TLS_PSK_WITH_AES_128_CCM
			0xc0a8, // TLS_PSK_WITH_AES_128_CCM_8
			0xa8,   // TLS_PSK_WITH_AES_128_GCM_SHA256
			0x8d,   // TLS_PSK_WITH_AES_256_CBC_SHA
			0xaf,   // TLS_PSK_WITH_AES_256_CBC_SHA384
			0xc0a5, // TLS_PSK_WITH_AES_256_CCM
			0xc0a9, // TLS_PSK_WITH_AES_256_CCM_8
			0xa9,   // TLS_PSK_WITH_AES_256_GCM_SHA384
			0xc064, // TLS_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06a, // TLS_PSK_WITH_ARIA_128_GCM_SHA256
			0xc065, // TLS_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06b, // TLS_PSK_WITH_ARIA_256_GCM_SHA384
			0xc094, // TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc08e, // TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc095, // TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc08f, // TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccab, // TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
			0x93,   // TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
			0x94,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA
			0xb6,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
			0xac,   // TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
			0x95,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA
			0xb7,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
			0xad,   // TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
			0xc068, // TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06e, // TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
			0xc069, // TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06f, // TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
			0xc098, // TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc092, // TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc099, // TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc093, // TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccae, // TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
			0xa,    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			0x2f,   // TLS_RSA_WITH_AES_128_CBC_SHA
			0x3c,   // TLS_RSA_WITH_AES_128_CBC_SHA256
			0xc09c, // TLS_RSA_WITH_AES_128_CCM
			0xc0a0, // TLS_RSA_WITH_AES_128_CCM_8
			0x9c,   // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x35,   // TLS_RSA_WITH_AES_256_CBC_SHA
			0x3d,   // TLS_RSA_WITH_AES_256_CBC_SHA256
			0xc09d, // TLS_RSA_WITH_AES_256_CCM
			0xc0a1, // TLS_RSA_WITH_AES_256_CCM_8
			0x9d,   // TLS_RSA_WITH_AES_256_GCM_SHA384
			0xc03c, // TLS_RSA_WITH_ARIA_128_CBC_SHA256
			0xc050, // TLS_RSA_WITH_ARIA_128_GCM_SHA256
			0xc03d, // TLS_RSA_WITH_ARIA_256_CBC_SHA384
			0xc051, // TLS_RSA_WITH_ARIA_256_GCM_SHA384
			0x41,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xba,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07a, // TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x84,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc0,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07b, // TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x7,    // TLS_RSA_WITH_IDEA_CBC_SHA
			0x96,   // TLS_RSA_WITH_SEED_CBC_SHA
			0xc01c, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
			0xc01f, // TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
			0xc022, // TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
			0xc01b, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
			0xc01e, // TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
			0xc021, // TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
			0xc01a, // TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
			0xc01d, // TLS_SRP_SHA_WITH_AES_128_CBC_SHA
			0xc020, // TLS_SRP_SHA_WITH_AES_256_CBC_SHA
			0x19,   // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
			0x17,   // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
			0x1b,   // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
			0x34,   // TLS_DH_anon_WITH_AES_128_CBC_SHA
			0x6c,   // TLS_DH_anon_WITH_AES_128_CBC_SHA256
			0xa6,   // TLS_DH_anon_WITH_AES_128_GCM_SHA256
			0x3a,   // TLS_DH_anon_WITH_AES_256_CBC_SHA
			0x6d,   // TLS_DH_anon_WITH_AES_256_CBC_SHA256
			0xa7,   // TLS_DH_anon_WITH_AES_256_GCM_SHA384
			0xc046, // TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
			0xc05a, // TLS_DH_anon_WITH_ARIA_128_GCM_SHA256
			0xc047, // TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
			0xc05b, // TLS_DH_anon_WITH_ARIA_256_GCM_SHA384
			0x46,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
			0xbf,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
			0xc084, // TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256
			0x89,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
			0xc5,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
			0xc085, // TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384
			0x1a,   // TLS_DH_anon_WITH_DES_CBC_SHA
			0x18,   // TLS_DH_anon_WITH_RC4_128_MD5
			0x9b,   // TLS_DH_anon_WITH_SEED_CBC_SHA
			0xb,    // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
			0xc,    // TLS_DH_DSS_WITH_DES_CBC_SHA
			0x11,   // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
			0x12,   // TLS_DHE_DSS_WITH_DES_CBC_SHA
			0x2d,   // TLS_DHE_PSK_WITH_NULL_SHA
			0xb4,   // TLS_DHE_PSK_WITH_NULL_SHA256
			0xb5,   // TLS_DHE_PSK_WITH_NULL_SHA384
			0x8e,   // TLS_DHE_PSK_WITH_RC4_128_SHA
			0x14,   // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x15,   // TLS_DHE_RSA_WITH_DES_CBC_SHA
			0xe,    // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
			0xf,    // TLS_DH_RSA_WITH_DES_CBC_SHA
			0xc017, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
			0xc018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
			0xc019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
			0xc015, // TLS_ECDH_anon_WITH_NULL_SHA
			0xc016, // TLS_ECDH_anon_WITH_RC4_128_SHA
			0xc001, // TLS_ECDH_ECDSA_WITH_NULL_SHA
			0xc002, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
			0xc006, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
			0xc007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
			0xc039, // TLS_ECDHE_PSK_WITH_NULL_SHA
			0xc03a, // TLS_ECDHE_PSK_WITH_NULL_SHA256
			0xc03b, // TLS_ECDHE_PSK_WITH_NULL_SHA384
			0xc033, // TLS_ECDHE_PSK_WITH_RC4_128_SHA
			0xc010, // TLS_ECDHE_RSA_WITH_NULL_SHA
			0xc011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
			0xc00b, // TLS_ECDH_RSA_WITH_NULL_SHA
			0xc00c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
			0xc102, // TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
			0xc100, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
			0xc103, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
			0xc105, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
			0xc101, // TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
			0xc104, // TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
			0xc106, // TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
			0x29,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
			0x26,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
			0x2a,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
			0x27,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
			0x2b,   // TLS_KRB5_EXPORT_WITH_RC4_40_MD5
			0x28,   // TLS_KRB5_EXPORT_WITH_RC4_40_SHA
			0x23,   // TLS_KRB5_WITH_3DES_EDE_CBC_MD5
			0x22,   // TLS_KRB5_WITH_DES_CBC_MD5
			0x1e,   // TLS_KRB5_WITH_DES_CBC_SHA
			0x25,   // TLS_KRB5_WITH_IDEA_CBC_MD5
			0x24,   // TLS_KRB5_WITH_RC4_128_MD5
			0x20,   // TLS_KRB5_WITH_RC4_128_SHA
			0x0,    // TLS_NULL_WITH_NULL_NULL
			0x2c,   // TLS_PSK_WITH_NULL_SHA
			0xb0,   // TLS_PSK_WITH_NULL_SHA256
			0xb1,   // TLS_PSK_WITH_NULL_SHA384
			0x8a,   // TLS_PSK_WITH_RC4_128_SHA
			0x8,    // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x6,    // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
			0x3,    // TLS_RSA_EXPORT_WITH_RC4_40_MD5
			0x2e,   // TLS_RSA_PSK_WITH_NULL_SHA
			0xb8,   // TLS_RSA_PSK_WITH_NULL_SHA256
			0xb9,   // TLS_RSA_PSK_WITH_NULL_SHA384
			0x92,   // TLS_RSA_PSK_WITH_RC4_128_SHA
			0x9,    // TLS_RSA_WITH_DES_CBC_SHA
			0x1,    // TLS_RSA_WITH_NULL_MD5
			0x2,    // TLS_RSA_WITH_NULL_SHA
			0x3b,   // TLS_RSA_WITH_NULL_SHA256
			0x4,    // TLS_RSA_WITH_RC4_128_MD5
			0x5,    // TLS_RSA_WITH_RC4_128_SHA
		},
		"TLSv1.3": {
			0xd,    // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
			0x30,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA
			0x3e,   // TLS_DH_DSS_WITH_AES_128_CBC_SHA256
			0xa4,   // TLS_DH_DSS_WITH_AES_128_GCM_SHA256
			0x36,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA
			0x68,   // TLS_DH_DSS_WITH_AES_256_CBC_SHA256
			0xa5,   // TLS_DH_DSS_WITH_AES_256_GCM_SHA384
			0xc03e, // TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
			0xc058, // TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256
			0xc03f, // TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
			0xc059, // TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384
			0x42,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbb,   // TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0xc082, // TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
			0x85,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc1,   // TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0xc083, // TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
			0x97,   // TLS_DH_DSS_WITH_SEED_CBC_SHA
			0x13,   // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
			0x32,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			0x40,   // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
			0xa2,   // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
			0x38,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0x6a,   // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
			0xa3,   // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
			0xc042, // TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
			0xc056, // TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
			0xc043, // TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
			0xc057, // TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
			0x44,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
			0xbd,   // TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
			0xc080, // TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
			0x87,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
			0xc3,   // TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
			0xc081, // TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
			0x99,   // TLS_DHE_DSS_WITH_SEED_CBC_SHA
			0x8f,   // TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
			0x90,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA
			0xb2,   // TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
			0xc0a6, // TLS_DHE_PSK_WITH_AES_128_CCM
			0xaa,   // TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
			0x91,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA
			0xb3,   // TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
			0xc0a7, // TLS_DHE_PSK_WITH_AES_256_CCM
			0xab,   // TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
			0xc066, // TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06c, // TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
			0xc067, // TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06d, // TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
			0xc096, // TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc090, // TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc097, // TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc091, // TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccad, // TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
			0x16,   // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
			0x33,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x67,   // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
			0xc09e, // TLS_DHE_RSA_WITH_AES_128_CCM
			0xc0a2, // TLS_DHE_RSA_WITH_AES_128_CCM_8
			0x9e,   // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
			0x39,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x6b,   // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
			0xc09f, // TLS_DHE_RSA_WITH_AES_256_CCM
			0xc0a3, // TLS_DHE_RSA_WITH_AES_256_CCM_8
			0x9f,   // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			0xc044, // TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc052, // TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xc045, // TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc053, // TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
			0x45,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbe,   // TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07c, // TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x88,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc4,   // TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07d, // TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0xccaa, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0x9a,   // TLS_DHE_RSA_WITH_SEED_CBC_SHA
			0x10,   // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
			0x31,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA
			0x3f,   // TLS_DH_RSA_WITH_AES_128_CBC_SHA256
			0xa0,   // TLS_DH_RSA_WITH_AES_128_GCM_SHA256
			0x37,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA
			0x69,   // TLS_DH_RSA_WITH_AES_256_CBC_SHA256
			0xa1,   // TLS_DH_RSA_WITH_AES_256_GCM_SHA384
			0xc040, // TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc054, // TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256
			0xc041, // TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
			0xc055, // TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384
			0x43,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xbc,   // TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07e, // TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x86,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc2,   // TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07f, // TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x98,   // TLS_DH_RSA_WITH_SEED_CBC_SHA
			0xc003, // TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc004, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
			0xc025, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
			0xc02d, // TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
			0xc005, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
			0xc026, // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
			0xc02e, // TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
			0xc04a, // TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc05e, // TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
			0xc04b, // TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc05f, // TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
			0xc074, // TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc088, // TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
			0xc075, // TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc089, // TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
			0xc008, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
			0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
			0xc023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
			0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0xc048, // TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xc049, // TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
			0xc072, // TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc073, // TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc034, // TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
			0xc035, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
			0xc037, // TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
			0xc036, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
			0xc038, // TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
			0xc070, // TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
			0xc071, // TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
			0xc09a, // TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc09b, // TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc012, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
			0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
			0xc027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
			0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0xc04c, // TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xc04d, // TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
			0xc076, // TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc077, // TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc00d, // TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
			0xc00e, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
			0xc029, // TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
			0xc031, // TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
			0xc00f, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
			0xc02a, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
			0xc032, // TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
			0xc04e, // TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
			0xc062, // TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
			0xc04f, // TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
			0xc063, // TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
			0xc078, // TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc08c, // TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0xc079, // TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
			0xc08d, // TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x1f,   // TLS_KRB5_WITH_3DES_EDE_CBC_SHA
			0x21,   // TLS_KRB5_WITH_IDEA_CBC_SHA
			0xc0aa, // TLS_PSK_DHE_WITH_AES_128_CCM_8
			0xc0ab, // TLS_PSK_DHE_WITH_AES_256_CCM_8
			0x8b,   // TLS_PSK_WITH_3DES_EDE_CBC_SHA
			0x8c,   // TLS_PSK_WITH_AES_128_CBC_SHA
			0xae,   // TLS_PSK_WITH_AES_128_CBC_SHA256
			0xc0a4, // TLS_PSK_WITH_AES_128_CCM
			0xc0a8, // TLS_PSK_WITH_AES_128_CCM_8
			0xa8,   // TLS_PSK_WITH_AES_128_GCM_SHA256
			0x8d,   // TLS_PSK_WITH_AES_256_CBC_SHA
			0xaf,   // TLS_PSK_WITH_AES_256_CBC_SHA384
			0xc0a5, // TLS_PSK_WITH_AES_256_CCM
			0xc0a9, // TLS_PSK_WITH_AES_256_CCM_8
			0xa9,   // TLS_PSK_WITH_AES_256_GCM_SHA384
			0xc064, // TLS_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06a, // TLS_PSK_WITH_ARIA_128_GCM_SHA256
			0xc065, // TLS_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06b, // TLS_PSK_WITH_ARIA_256_GCM_SHA384
			0xc094, // TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc08e, // TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc095, // TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc08f, // TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccab, // TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
			0x93,   // TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
			0x94,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA
			0xb6,   // TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
			0xac,   // TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
			0x95,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA
			0xb7,   // TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
			0xad,   // TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
			0xc068, // TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
			0xc06e, // TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
			0xc069, // TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
			0xc06f, // TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
			0xc098, // TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
			0xc092, // TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
			0xc099, // TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
			0xc093, // TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
			0xccae, // TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
			0xa,    // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			0x2f,   // TLS_RSA_WITH_AES_128_CBC_SHA
			0x3c,   // TLS_RSA_WITH_AES_128_CBC_SHA256
			0xc09c, // TLS_RSA_WITH_AES_128_CCM
			0xc0a0, // TLS_RSA_WITH_AES_128_CCM_8
			0x9c,   // TLS_RSA_WITH_AES_128_GCM_SHA256
			0x35,   // TLS_RSA_WITH_AES_256_CBC_SHA
			0x3d,   // TLS_RSA_WITH_AES_256_CBC_SHA256
			0xc09d, // TLS_RSA_WITH_AES_256_CCM
			0xc0a1, // TLS_RSA_WITH_AES_256_CCM_8
			0x9d,   // TLS_RSA_WITH_AES_256_GCM_SHA384
			0xc03c, // TLS_RSA_WITH_ARIA_128_CBC_SHA256
			0xc050, // TLS_RSA_WITH_ARIA_128_GCM_SHA256
			0xc03d, // TLS_RSA_WITH_ARIA_256_CBC_SHA384
			0xc051, // TLS_RSA_WITH_ARIA_256_GCM_SHA384
			0x41,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
			0xba,   // TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
			0xc07a, // TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
			0x84,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
			0xc0,   // TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
			0xc07b, // TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
			0x7,    // TLS_RSA_WITH_IDEA_CBC_SHA
			0x96,   // TLS_RSA_WITH_SEED_CBC_SHA
			0xc01c, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
			0xc01f, // TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
			0xc022, // TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
			0xc01b, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
			0xc01e, // TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
			0xc021, // TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
			0xc01a, // TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
			0xc01d, // TLS_SRP_SHA_WITH_AES_128_CBC_SHA
			0xc020, // TLS_SRP_SHA_WITH_AES_256_CBC_SHA
			0x19,   // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
			0x17,   // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
			0x1b,   // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
			0x34,   // TLS_DH_anon_WITH_AES_128_CBC_SHA
			0x6c,   // TLS_DH_anon_WITH_AES_128_CBC_SHA256
			0xa6,   // TLS_DH_anon_WITH_AES_128_GCM_SHA256
			0x3a,   // TLS_DH_anon_WITH_AES_256_CBC_SHA
			0x6d,   // TLS_DH_anon_WITH_AES_256_CBC_SHA256
			0xa7,   // TLS_DH_anon_WITH_AES_256_GCM_SHA384
			0xc046, // TLS_DH_anon_WITH_ARIA_128_CBC_SHA256
			0xc05a, // TLS_DH_anon_WITH_ARIA_128_GCM_SHA256
			0xc047, // TLS_DH_anon_WITH_ARIA_256_CBC_SHA384
			0xc05b, // TLS_DH_anon_WITH_ARIA_256_GCM_SHA384
			0x46,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA
			0xbf,   // TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256
			0xc084, // TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256
			0x89,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA
			0xc5,   // TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256
			0xc085, // TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384
			0x1a,   // TLS_DH_anon_WITH_DES_CBC_SHA
			0x18,   // TLS_DH_anon_WITH_RC4_128_MD5
			0x9b,   // TLS_DH_anon_WITH_SEED_CBC_SHA
			0xb,    // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
			0xc,    // TLS_DH_DSS_WITH_DES_CBC_SHA
			0x11,   // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
			0x12,   // TLS_DHE_DSS_WITH_DES_CBC_SHA
			0x2d,   // TLS_DHE_PSK_WITH_NULL_SHA
			0xb4,   // TLS_DHE_PSK_WITH_NULL_SHA256
			0xb5,   // TLS_DHE_PSK_WITH_NULL_SHA384
			0x8e,   // TLS_DHE_PSK_WITH_RC4_128_SHA
			0x14,   // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x15,   // TLS_DHE_RSA_WITH_DES_CBC_SHA
			0xe,    // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
			0xf,    // TLS_DH_RSA_WITH_DES_CBC_SHA
			0xc017, // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
			0xc018, // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
			0xc019, // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
			0xc015, // TLS_ECDH_anon_WITH_NULL_SHA
			0xc016, // TLS_ECDH_anon_WITH_RC4_128_SHA
			0xc001, // TLS_ECDH_ECDSA_WITH_NULL_SHA
			0xc002, // TLS_ECDH_ECDSA_WITH_RC4_128_SHA
			0xc006, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
			0xc007, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
			0xc039, // TLS_ECDHE_PSK_WITH_NULL_SHA
			0xc03a, // TLS_ECDHE_PSK_WITH_NULL_SHA256
			0xc03b, // TLS_ECDHE_PSK_WITH_NULL_SHA384
			0xc033, // TLS_ECDHE_PSK_WITH_RC4_128_SHA
			0xc010, // TLS_ECDHE_RSA_WITH_NULL_SHA
			0xc011, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
			0xc00b, // TLS_ECDH_RSA_WITH_NULL_SHA
			0xc00c, // TLS_ECDH_RSA_WITH_RC4_128_SHA
			0xc102, // TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
			0xc100, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
			0xc103, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
			0xc105, // TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
			0xc101, // TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
			0xc104, // TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
			0xc106, // TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
			0x29,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
			0x26,   // TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
			0x2a,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
			0x27,   // TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
			0x2b,   // TLS_KRB5_EXPORT_WITH_RC4_40_MD5
			0x28,   // TLS_KRB5_EXPORT_WITH_RC4_40_SHA
			0x23,   // TLS_KRB5_WITH_3DES_EDE_CBC_MD5
			0x22,   // TLS_KRB5_WITH_DES_CBC_MD5
			0x1e,   // TLS_KRB5_WITH_DES_CBC_SHA
			0x25,   // TLS_KRB5_WITH_IDEA_CBC_MD5
			0x24,   // TLS_KRB5_WITH_RC4_128_MD5
			0x20,   // TLS_KRB5_WITH_RC4_128_SHA
			0x0,    // TLS_NULL_WITH_NULL_NULL
			0x2c,   // TLS_PSK_WITH_NULL_SHA
			0xb0,   // TLS_PSK_WITH_NULL_SHA256
			0xb1,   // TLS_PSK_WITH_NULL_SHA384
			0x8a,   // TLS_PSK_WITH_RC4_128_SHA
			0x8,    // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
			0x6,    // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
			0x3,    // TLS_RSA_EXPORT_WITH_RC4_40_MD5
			0x2e,   // TLS_RSA_PSK_WITH_NULL_SHA
			0xb8,   // TLS_RSA_PSK_WITH_NULL_SHA256
			0xb9,   // TLS_RSA_PSK_WITH_NULL_SHA384
			0x92,   // TLS_RSA_PSK_WITH_RC4_128_SHA
			0x9,    // TLS_RSA_WITH_DES_CBC_SHA
			0x1,    // TLS_RSA_WITH_NULL_MD5
			0x2,    // TLS_RSA_WITH_NULL_SHA
			0x3b,   // TLS_RSA_WITH_NULL_SHA256
			0x4,    // TLS_RSA_WITH_RC4_128_MD5
			0x5,    // TLS_RSA_WITH_RC4_128_SHA
			0xc0b4, // TLS_SHA256_SHA256
			0xc0b5, // TLS_SHA384_SHA384
			0xc7,   // TLS_SM4_CCM_SM3
			0xc6,   // TLS_SM4_GCM_SM3
		},
	}
}

// GetMetaFile returns the file to which metadata should be output
func GetMetaFile() *os.File {
	return config.metaFile
}

func includeDebugOutput() bool {
	return config.Debug
}
