package util

import (
	"regexp"
	"strings"
)

func NormalizeUrl(url string) string {
	modified := strings.ToLower(url)
	reg := regexp.MustCompile("^http(|s)://")
	if reg.FindStringIndex(modified) == nil {
		modified = "https://" + modified
	} else {
		modified = reg.ReplaceAllString(modified, "https://")
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}
	return modified
}
