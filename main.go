package main

import (
	"flag"
	"fmt"
	"os"

	detector "dd-log-detector/pkg"
)

var (
	help      bool
	filePath  string
	threshold string
)

func init() {
	flag.BoolVar(&help, "h", false, "Show this help dialogue.")
	flag.StringVar(&filePath, "f", "", "Path to the csv file containing log events to analyze.")
	flag.StringVar(&threshold, "t", "", "Threshold of findings to trigger an alert")
	flag.Parse()
}

func main() {
	// Check for proper arguments
	if help || filePath == "" {
		fmt.Printf("Usage: %s -f <log_file>\n", os.Args[0])
		os.Exit(1)
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("File not found: %s\n", filePath)
		os.Exit(1)
	}

	// Run a detector on the given file
	config := detector.Config{LogFile: filePath}
	d := detector.New(&config)
	d.Run()
}
