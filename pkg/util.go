package detector

import "strings"

// Helper to check if a string is in a slice
func isOneOf(s string, l []string) bool {
	for _, item := range l {
		if s == item {
			return true
		}
	}
	return false
}

// Helper to check if a string contains a value in a slice
func containsOneOf(s string, l []string) bool {
	for _, item := range l {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

// Helper to check if a string contains a value in a slice
func suffixOneOf(s string, l []string) bool {
	for _, item := range l {
		if strings.HasSuffix(s, item) {
			return true
		}
	}
	return false
}

// Checks for commands related to making web requests
func isWebRequest(cmd []string) bool {
	command := stripSudo(cmd)
	return isOneOf(command[0], []string{"wget", "curl"})
}

// Checks for commands related to reading/modifying files
func isFileRead(cmd []string) bool {
	command := stripSudo(cmd)
	var readCommands = []string{"cat", "cmp", "ls", "less",
		"cp", "mv", "chmod", "chown", "find"}
	return isOneOf(command[0], readCommands)
}

func stripSudo(cmd []string) []string {
	if cmd[0] == "sudo" {
		return cmd[1:]
	}
	return cmd
}
