package detector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataDetectorEC2(t *testing.T) {
	ioc := &MetadataRead{
		Path:  "",
		Mitre: "T1552.005",
		IOC: IOC{
			name:        "Metadata Service Read",
			description: "An attempt has been made to read potentially sensitive information from the cloud metadata service",
		},
	}

	d := Data{
		Cmdline: []string{"curl", "https://169.254.169.254/latest"},
	}

	assert.Equal(t, true, ioc.Detect(d))
	assert.Equal(t, "EC2", ioc.Service)
}

func TestMetadataDetectorECS(t *testing.T) {
	ioc := &MetadataRead{
		Path:  "",
		Mitre: "T1552.005",
		IOC: IOC{
			name:        "Metadata Service Read",
			description: "An attempt has been made to read potentially sensitive information from the cloud metadata service",
		},
	}

	d := Data{
		Cmdline: []string{"curl", "https://169.254.170.2/latest"},
	}

	assert.Equal(t, true, ioc.Detect(d))
	assert.Equal(t, "ECS", ioc.Service)
}
