package detector

import "time"

// Config is a configuration for a detector
type Config struct {
	LogFile string
}

// Detector is an instance of the security event log parser
type Detector struct {
	config     *Config
	alertCache map[string]bool
	data       chan Data
	alerts     chan Alert
	done       chan bool
}

// Data represents log events
type Data struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Cmdline   []string  `json:"cmdline"`
	Username  string    `json:"username"`
	ExitCode  int       `json:"exit_code"`
	Ppid      int       `json:"ppid"`
	Pid       int       `json:"pid"`
	Auid      int       `json:"auid"`
	UID       int       `json:"uid"`
	Gid       int       `json:"gid"`
	Euid      int       `json:"euid"`
	Suid      int       `json:"suid"`
	Fsuid     int       `json:"fsuid"`
	Egid      int       `json:"egid"`
	Sgid      int       `json:"sgid"`
	Fsgid     int       `json:"fsgid"`
}

// Severity represents the severity of an alert
type Severity int

const (
	Informational Severity = iota
	Low
	Medium
	High
	Critical
)

// Alert represents a security alert
type Alert struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Timestamp   time.Time   `json:"timestamp"`
	Cmdline     string      `json:"cmdline"`
	Username    string      `json:"username"`
	ExitCode    int         `json:"exit_code"`
	Ppid        int         `json:"ppid"`
	Pid         int         `json:"pid"`
	Severity    Severity    `json:"severity"`
	Detail      interface{} `json:"detail"`
}

// Indicator represents logic to trigger alerts
type Indicator interface {
	// Detect checks for activity in line with the IOC
	Detect(Data) bool

	// Alert creates a security alert
	Alert(Data) Alert
}

// IOC represents an indicator of compromise
type IOC struct {
	name        string
	description string
}

// MetadataRead represents activity showing an attempt read the cloud metadata service
type MetadataRead struct {
	Path    string `json:"path"`
	Service string `json:"service"`
	Mitre   string `json:"mitre"`
	IOC
}

// CookieExport represents activity showing an attempt to export web session cookies
type CookieExport struct {
	CookieSource string `json:"cookie_source"`
	ExportPath   string `json:"export_filepath"`
	Mitre        string `json:"mitre"`
	IOC
}

// SensitiveFileRead represents activity showing an attempt to read sensitive files
type SensitiveFileRead struct {
	FilePath string `json:"filepath"`
	Mitre    string `json:"mitre"`
	IOC
}

// SuspiciousDownloadFromInternet represents activity showing an attempt to download a
// suspicious file from a remote location
type SuspiciousDownloadFromInternet struct {
	FileName string `json:"filename"`
	URL      string `json:"url"`
	Mitre    string `json:"mitre"`
	IOC
}
