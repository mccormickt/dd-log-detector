package detector

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Parse reads lines of a log file into a structured Data channel
func (d *Detector) Parse(file *os.File) {
	defer file.Close()
	defer close(d.data)

	// Read csv headers
	reader := csv.NewReader(file)
	_, err := reader.Read()
	if err != nil {
		log.Fatalf("Cannot read file: %s\n", file.Name())
		return
	}

	// Parse each line of the logfile
	for {
		line, err := reader.Read()
		if err == io.EOF {
			log.Println("Finished reading logs")
			return
		} else if err != nil {
			log.Fatalf("Cannot read file: %s\n", file.Name())
		}

		// Format timestamp
		timestamp, err := time.Parse("2006-01-02 15:04:05+00", line[1])
		if err != nil {
			log.Fatalln(err)
			return
		}

		// Unescape url encoded data in command field
		cmdline, err := url.QueryUnescape(line[2])
		if err != nil {
			log.Fatalln(err)
			return
		}

		// Parse rest of data
		id, err := strconv.Atoi(line[0])
		exitCode, err := strconv.Atoi(line[4])
		ppid, err := strconv.Atoi(line[5])
		pid, err := strconv.Atoi(line[6])
		auid, err := strconv.Atoi(line[7])
		uid, err := strconv.Atoi(line[8])
		gid, err := strconv.Atoi(line[9])
		euid, err := strconv.Atoi(line[10])
		suid, err := strconv.Atoi(line[11])
		fsuid, err := strconv.Atoi(line[12])
		egid, err := strconv.Atoi(line[13])
		sgid, err := strconv.Atoi(line[14])
		fsgid, err := strconv.Atoi(line[15])
		if err != nil {
			log.Fatalln(err)
		}

		// Push data to channel
		d.data <- Data{
			ID:        id,
			Timestamp: timestamp,
			Cmdline:   strings.Fields(cmdline),
			Username:  line[3],
			ExitCode:  exitCode,
			Ppid:      ppid,
			Pid:       pid,
			Auid:      auid,
			UID:       uid,
			Gid:       gid,
			Euid:      euid,
			Suid:      suid,
			Fsuid:     fsuid,
			Egid:      egid,
			Sgid:      sgid,
			Fsgid:     fsgid,
		}
	}
}

// Detect reads log data and sends security alerts to a channel
func (d *Detector) Detect() {
	defer close(d.alerts)

	// Check for all IOCs
	for event := range d.data {
		// Read events from log
		for _, ioc := range GetIndicators() {
			if ioc.Detect(event) {
				alert := ioc.Alert(event)

				// Check if we've alerted on this activity already
				identifier := alert.Name + alert.Username + alert.Cmdline
				if _, ok := d.alertCache[identifier]; ok {
					continue
				}

				// If we haven't, cut an alert and add to the cache
				d.alerts <- alert
				d.alertCache[identifier] = true
			}
		}
	}

	// Signal that we're done processing logs
	log.Println("Finished processing log events")
}

// Alert sends security alerts to the proper destination for remediation
func (d *Detector) Alert() {
	for alert := range d.alerts {
		notify, err := json.Marshal(alert)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(notify))
	}
	log.Println("Finished sending security alerts")

	// Signal the end of the detection pipeline
	d.done <- true
}

// New creates a new instance of a detector
func New(config *Config) *Detector {
	return &Detector{
		config:     config,
		alertCache: make(map[string]bool),
		data:       make(chan Data),
		alerts:     make(chan Alert),
		done:       make(chan bool),
	}
}

// Run runs the detector to start ingesting log events
func (d *Detector) Run() {
	log.Printf("Reading alerts from %s\n", d.config.LogFile)
	file, err := os.Open(d.config.LogFile)
	if err != nil {
		log.Fatalf("Cannot read file: %s\n", d.config.LogFile)
		return
	}

	// Parse the log file
	go d.Parse(file)

	// Produce alerts from log data
	go d.Detect()

	// Processes alerts triggered from detections
	go d.Alert()

	// Wait until we're done processing logs and alerts
	<-d.done
}
