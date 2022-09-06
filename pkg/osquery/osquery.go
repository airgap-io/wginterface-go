package osquery

import "runtime"

type OsAirgapQuery interface {
	GetOSVersion() (string, error)
	GetInstalledApps() ([]string, error)
	GetInstalledAntiVirusProducts() ([]string, error)
	GetActiveDirectories() ([]string, error)
	GetProtectionStatus() (bool, error)
	GetFirewallStatus() (bool, error)
	GetAllowScreenLockStatus() (int, error)
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
