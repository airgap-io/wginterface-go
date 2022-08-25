package osquery

import "runtime"

type Osquery interface {
	DetectOS() string
}

//find the OS type
func DetectOS() string {
	os := runtime.GOOS
	switch os {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	case "linux":
		return "linux"
	default:
		return "linux"

	}
}
