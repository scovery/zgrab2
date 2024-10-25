package zgrab2

import (
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// Config is the high level framework options that will be parsed
// from the command line
type Config struct {
	OutputFileName     string          `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName      string          `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	MetaFileName       string          `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr"`
	LogFileName        string          `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	Senders            int             `short:"s" long:"senders" default:"1000" description:"Number of send goroutines to use"`
	Debug              bool            `long:"debug" description:"Include debug fields in the output."`
	Flush              bool            `long:"flush" description:"Flush after each line of output."`
	GOMAXPROCS         int             `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	ConnectionsPerHost int             `long:"connections-per-host" default:"1" description:"Number of times to connect to each host (results in more output)"`
	ReadLimitPerHost   int             `long:"read-limit-per-host" default:"96" description:"Maximum total kilobytes to read for a single host (default 96kb)"`
	Prometheus         string          `long:"prometheus" description:"Address to use for Prometheus server (e.g. localhost:8080). If empty, Prometheus is disabled."`
	CustomDNS          string          `long:"dns" description:"Address of a custom DNS server for lookups. Default port is 53."`
	Multiple           MultipleCommand `command:"multiple" description:"Multiple module actions"`
	inputFile          *os.File
	outputFile         *os.File
	metaFile           *os.File
	logFile            *os.File
	inputTargets       InputTargetsFunc
	outputResults      OutputResultsFunc
	localAddr          *net.TCPAddr
	WeakCSList         map[string][]uint16
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

func validateFrameworkConfiguration() {
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
	} else {
		var err error
		if config.metaFile, err = os.Create(config.MetaFileName); err != nil {
			log.Fatal(err)
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
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(config.Prometheus, nil); err != nil {
				log.Fatalf("could not run prometheus server: %s", err.Error())
			}
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

	// Validate custom DNS
	if config.CustomDNS != "" {
		var err error
		if config.CustomDNS, err = addDefaultPortToDNSServerName(config.CustomDNS); err != nil {
			log.Fatalf("invalid DNS server address: %s", err)
		}
	}

	config.WeakCSList = map[string][]uint16{
		"SSLv3": {
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
			0x1b, 0x34, 0x3a, 0x46, 0xbf, 0x89, 0xc5, 0x9b, 0x13, 0x32, 0x38, 0x44,
			0xbd, 0x87, 0xc3, 0x99, 0x8f, 0x90, 0xb2, 0x91, 0xb3, 0xc096, 0xc097,
			0x2d, 0xb4, 0xb5, 0x16, 0x33, 0x39, 0x45, 0xbe, 0x88, 0xc4, 0x9a,
			0xc017, 0xc018, 0xc019, 0xc015, 0xc008, 0xc009, 0xc00a, 0xc006, 0xc034,
			0xc035, 0xc037, 0xc036, 0xc038, 0xc09a, 0xc09b, 0xc039, 0xc03a, 0xc03b,
			0xc012, 0xc013, 0xc014, 0xc010, 0x8b, 0x8c, 0xae, 0x8d, 0xaf, 0xc094,
			0xc095, 0x2c, 0xb0, 0xb1, 0x93, 0x94, 0xb6, 0x95, 0xb7, 0xc098, 0xc099,
			0x2e, 0xb8, 0xb9, 0xa, 0x2f, 0x35, 0x41, 0xba, 0x84, 0xc0, 0x7, 0x1,
			0x2, 0x96, 0xc01c, 0xc01f, 0xc022, 0xc01b, 0xc01e, 0xc021, 0xc01a, 0xc01d,
			0xc020,
		},
		"TLSv1.1": {
			0x1b, 0x34, 0x3a, 0x46, 0xbf, 0x89, 0xc5, 0x9b, 0x13, 0x32, 0x38, 0x44,
			0xbd, 0x87, 0xc3, 0x99, 0x8f, 0x90, 0xb2, 0x91, 0xb3, 0xc096, 0xc097,
			0x2d, 0xb4, 0xb5, 0x16, 0x33, 0x39, 0x45, 0xbe, 0x88, 0xc4, 0x9a,
			0xc017, 0xc018, 0xc019, 0xc015, 0xc008, 0xc009, 0xc00a, 0xc006, 0xc034,
			0xc035, 0xc037, 0xc036, 0xc038, 0xc09a, 0xc09b, 0xc039, 0xc03a, 0xc03b,
			0xc012, 0xc013, 0xc014, 0xc010, 0x8b, 0x8c, 0xae, 0x8d, 0xaf, 0xc094,
			0xc095, 0x2c, 0xb0, 0xb1, 0x93, 0x94, 0xb6, 0x95, 0xb7, 0xc098, 0xc099,
			0x2e, 0xb8, 0xb9, 0xa, 0x2f, 0x35, 0x41, 0xba, 0x84, 0xc0, 0x7, 0x1,
			0x2, 0x96, 0xc01c, 0xc01f, 0xc022, 0xc01b, 0xc01e, 0xc021, 0xc01a, 0xc01d,
			0xc020,
		},
		"TLSv1.2": {
			0x1b, 0x34, 0x6c, 0xa6, 0x3a, 0x6d, 0xa7, 0x46, 0xbf, 0x89, 0xc5, 0x9b,
			0x13, 0x32, 0x40, 0xa2, 0x38, 0x6a, 0xa3, 0x44, 0xbd, 0x87, 0xc3, 0x99,
			0x8f, 0x90, 0xb2, 0xc0a6, 0xaa, 0x91, 0xb3, 0xc0a7, 0xab, 0xc096, 0xc097,
			0xccad, 0x2d, 0xb4, 0xb5, 0x16, 0x33, 0x67, 0xc09e, 0xc0a2, 0x9e, 0x39,
			0x6b, 0xc09f, 0xc0a3, 0x9f, 0x45, 0xbe, 0x88, 0xc4, 0xccaa, 0x9a, 0xc017,
			0xc018, 0xc019, 0xc015, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b,
			0xc00a, 0xc024, 0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0xc006,
			0xc034, 0xc035, 0xc037, 0xc036, 0xc038, 0xc09a, 0xc09b, 0xccac, 0xc039,
			0xc03a, 0xc03b, 0xc012, 0xc013, 0xc027, 0xc02f, 0xc014, 0xc028, 0xc030,
			0xc076, 0xc077, 0xcca8, 0xc010, 0xc0aa, 0xc0ab, 0x8b, 0x8c, 0xae, 0xc0a4,
			0xc0a8, 0xa8, 0x8d, 0xaf, 0xc0a5, 0xc0a9, 0xa9, 0xc094, 0xc095, 0xccab,
			0x2c, 0xb0, 0xb1, 0x93, 0x94, 0xb6, 0xac, 0x95, 0xb7, 0xad, 0xc098,
			0xc099, 0xccae, 0x2e, 0xb8, 0xb9, 0xa, 0x2f, 0x3c, 0xc09c, 0xc0a0, 0x9c,
			0x35, 0x3d, 0xc09d, 0xc0a1, 0x9d, 0x41, 0xba, 0x84, 0xc0, 0x7, 0x1, 0x2,
			0x3b, 0x96, 0xc01c, 0xc01f, 0xc022, 0xc01b, 0xc01e, 0xc021, 0xc01a, 0xc01d,
			0xc020,
		},
		"TLSv1.3": {
			0x1304, 0x1301, 0x1302,
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
