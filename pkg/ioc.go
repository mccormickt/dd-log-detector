package detector

import (
	"net/url"
	"strings"
)

// Detect a MetadataRead event
func (i *MetadataRead) Detect(d Data) bool {
	// Check for a web request event
	if !isWebRequest(d.Cmdline) {
		return false
	}
	for _, field := range d.Cmdline {
		if strings.Contains(field, "169.254.169.254") {
			i.Service = "EC2"
		} else if strings.Contains(field, "169.254.170.2") {
			i.Service = "ECS"
		}
		if i.Service != "" {
			u, err := url.ParseRequestURI(field)
			if err == nil {
				i.Path = u.EscapedPath()
				if i.Path == "" {
					i.Path = "/"
				}
				return true
			}
		}
	}
	return false
}

// Alert on a CookieExport event
func (i *MetadataRead) Alert(d Data) Alert {
	return Alert{
		Name:        i.name,
		Description: i.description,
		Timestamp:   d.Timestamp,
		Cmdline:     strings.Join(d.Cmdline, " "),
		Username:    d.Username,
		ExitCode:    d.ExitCode,
		Ppid:        d.Ppid,
		Pid:         d.Pid,
		Severity:    Low,
		Detail:      *i,
	}
}

// Detect a CookieExport event
func (i *CookieExport) Detect(d Data) bool {
	// Check for a web request event
	if !isWebRequest(d.Cmdline) {
		return false
	}
	for index, field := range d.Cmdline {
		if stripSudo(d.Cmdline)[0] == "curl" {
			if strings.Contains(field, "http") {
				// Record host as source of exported cookie
				u, err := url.ParseRequestURI(field)
				if err == nil {
					i.CookieSource = u.Host
				}
			}

			// Check for cookie export flags, record path it was saved to
			if field == "-b" || field == "--cookie-jar" {
				i.ExportPath = d.Cmdline[index+1]
			}

			// Trigger detection once we've got our information from command
			if i.ExportPath != "" && i.CookieSource != "" {
				return true
			}
		}
	}
	return false
}

// Alert on a CookieExport event
func (i *CookieExport) Alert(d Data) Alert {
	return Alert{
		Name:        i.name,
		Description: i.description,
		Timestamp:   d.Timestamp,
		Cmdline:     strings.Join(d.Cmdline, " "),
		Username:    d.Username,
		ExitCode:    d.ExitCode,
		Ppid:        d.Ppid,
		Pid:         d.Pid,
		Severity:    Medium,
		Detail:      *i,
	}
}

// Detect a SensitiveFileRead event
func (i *SensitiveFileRead) Detect(d Data) bool {
	// Check for a file read event
	if !isFileRead(d.Cmdline) {
		return false
	}
	for _, field := range d.Cmdline {
		// Check if command references sensitive file locations
		sensitive := []string{"/etc/passwd", "/etc/shadow",
			"/etc/gshadow", "/proc/", "/sys/"}
		if containsOneOf(field, sensitive) {
			i.FilePath = field
			return true
		}
	}
	return false
}

// Alert on a SensitiveFileRead event
func (i *SensitiveFileRead) Alert(d Data) Alert {
	severity := High
	if d.Username == "root" || d.Cmdline[0] == "sudo" {
		severity = Critical
	}
	return Alert{
		Name:        i.name,
		Description: i.description,
		Timestamp:   d.Timestamp,
		Cmdline:     strings.Join(d.Cmdline, " "),
		Username:    d.Username,
		ExitCode:    d.ExitCode,
		Ppid:        d.Ppid,
		Pid:         d.Pid,
		Severity:    severity,
		Detail:      *i,
	}
}

// Detect a SensitiveFileRead event
func (i *SuspiciousDownloadFromInternet) Detect(d Data) bool {
	// Check for a web request event
	if !isWebRequest(d.Cmdline) {
		return false
	}
	for _, field := range d.Cmdline {
		sites := []string{"github.com", "githubusercontent.com", "gitlab.com"}
		extensions := []string{".sh", ".bash", ".zip", ".gz", ".tar", ".tgz", ".rar"}
		if strings.Contains(field, "http") {
			// Parse out url for source host and file downloaded
			u, err := url.ParseRequestURI(field)
			if err == nil {
				// Get URI for file name and extension
				path := strings.Split(u.Path, "/")
				fileName := path[len(path)-1]

				// Detect github + suspicious extension, or exploit-db
				git := containsOneOf(u.Host, sites) &&
					(suffixOneOf(fileName, extensions) || strings.Contains(u.Path, "binaries"))
				if git || strings.Contains(u.Host, "exploit-db.com") {
					i.FileName = fileName
					i.URL = field
					return true
				}
			}
		}
	}
	return false
}

// Alert on a SensitiveFileRead event
func (i *SuspiciousDownloadFromInternet) Alert(d Data) Alert {
	return Alert{
		Name:        i.name,
		Description: i.description,
		Timestamp:   d.Timestamp,
		Cmdline:     strings.Join(d.Cmdline, " "),
		Username:    d.Username,
		ExitCode:    d.ExitCode,
		Ppid:        d.Ppid,
		Pid:         d.Pid,
		Severity:    High,
		Detail:      *i,
	}
}

// GetIndicators returns the Indicators of Compromise to look for in logs
func GetIndicators() []Indicator {
	return []Indicator{
		// Activity showing an attempt read the cloud metadata service
		&MetadataRead{
			Path:  "",
			Mitre: "T1552.005",
			IOC: IOC{
				name:        "Metadata Service Read",
				description: "An attempt has been made to read potentially sensitive information from the cloud metadata service",
			},
		},

		// Activity showing cookies being written to a file
		&CookieExport{
			CookieSource: "",
			ExportPath:   "",
			Mitre:        "T1552.001",
			IOC: IOC{
				name:        "Web Cookie Export",
				description: "An attempt has been made to export web session cookies",
			},
		},

		// Activity showing cookies being written to a file
		&SensitiveFileRead{
			FilePath: "",
			Mitre:    "T1003.008",
			IOC: IOC{
				name:        "Sensitive File Read",
				description: "An attempt has been made to read sensitive files",
			},
		},

		// Activity showing a suspicious download from a remote location
		&SuspiciousDownloadFromInternet{
			FileName: "",
			URL:      "",
			Mitre:    "T1059, T1082, T1592",
			IOC: IOC{
				name:        "Suspicious File Download",
				description: "A attempt has been made to download a suspicous file from a remote location",
			},
		},
	}
}
