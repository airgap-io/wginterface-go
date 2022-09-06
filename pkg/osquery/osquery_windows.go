package osquery

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type OSQueryWindows struct {
	OsName string `def:"linux"`
}

func (OS OSQueryWindows) GetOSVersion() (string, error) {
	command := "[System.Environment]::OSVersion.Version"
	output, err := exec.Command("powershell", command).Output()
	if err != nil {
		fmt.Println(err)
	}
	strArr1 := []string{}
	lineBytes := bytes.Split(output, []byte{'\n'})
	for _, line := range lineBytes {
		text := string(line)
		text = strings.TrimRight(text, "\r")
		if text != "" {
			strArr1 = append(strArr1, text)
		}
	}
	strArr2 := strings.Fields(strArr1[len(strArr1)-1])
	if len(strArr2) > 3 {
		return strings.Join(strArr2, "."), err
	}
	return "", err
}

func (OS OSQueryWindows) GetInstalledApps() ([]string, error) {
	command := "Get-AppxPackage | Select Name"
	output, err := exec.Command("powershell", command).Output()
	if err != nil {
		fmt.Println(err)
	}
	return getRequiredDataFromTable(output), err
}

func (OS OSQueryWindows) GetInstalledAntiVirusProducts() ([]string, error) {
	command := "Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct | select displayName"
	output, err := exec.Command("powershell", command).Output()
	if err != nil {
		fmt.Println(err)
	}
	return getRequiredDataFromTable(output), err
}

func (OS OSQueryWindows) GetActiveDirectories() ([]string, error) {
	command := "Import-Module ActiveDirectory | select Name"
	output, err := exec.Command("powershell", command).Output()
	if err != nil {
		fmt.Println(err)
	}
	return getRequiredDataFromTable(output), err
}
func (OS OSQueryWindows) GetProtectionStatus() (bool, error) {
	command := " Get-BitLockerVolume | select VolumeType,MountPoint,ProtectionStatus "
	output, err := exec.Command("powershell", command).Output()
	fmt.Println(output)
	if err != nil {
		fmt.Println(err)
	}
	return compareStrings(output, "on")
}

func (OS OSQueryWindows) GetFirewallStatus() (bool, error) {
	command := "Get-NetFirewallProfile | Select Name, Enabled"
	output, err := exec.Command("powershell", command).Output()
	if err != nil {
		fmt.Println(err)
	}
	return compareStrings(output, "true")
}

const regKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\`

func (OS OSQueryWindows) GetAllowScreenLockStatus() (int, error) {

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.QUERY_VALUE)
	if err != nil {
		return -1, fmt.Errorf("can't open registry key ")
	}
	defer k.Close()

	params, err := k.ReadValueNames(0)
	if err != nil {
		return -1, fmt.Errorf("can't ReadSubKeyNames ")
	}

	for _, param := range params {
		b := strings.Compare(param, "AllowLockScreen")
		if b == 0 {
			val, err := getRegistryValueAsString(k, param)
			if err != nil {
				return -1, fmt.Errorf("can't get registry as string ")
			}
			i, err := strconv.Atoi(val)
			return i, err
		}
	}
	return -1, err
}

func getRequiredDataFromTable(output []byte) []string {
	strArr1 := []string{}
	lineBytes := bytes.Split(output, []byte{'\n'})
	for _, line := range lineBytes {
		text := string(line)
		// as the top 2 rows are not to be considered ( headers)
		if text == "\r" || strings.Contains(text, "Name   ") || strings.Contains(text, "----  ") {
			continue
		}

		text = strings.TrimRight(text, "\r")
		if text != "" {
			strArr1 = append(strArr1, text)
		}
	}
	return strArr1
}

func compareStrings(output []byte, cmp1 string) (bool, error) {
	strArr1 := []string{}
	lineBytes := bytes.Split(output, []byte{'\n'})
	for _, line := range lineBytes {
		text := string(line)
		text = strings.TrimRight(text, "\r")
		if text != "" {
			strArr1 = append(strArr1, text)
		}
	}
	for _, line1 := range strArr1 {
		strArr2 := strings.Fields(line1)
		if len(strArr2) < 2 {
			continue
		}
		for _, line2 := range strArr2 {
			if line2 == " " {
				continue
			}
			b := strings.Compare(strings.ToLower(line2), cmp1)
			if b == 0 {
				return true, fmt.Errorf("ok")
			}
		}
	}
	return false, fmt.Errorf("not ok")
}

func getRegistryValueAsString(key registry.Key, subKey string) (string, error) {
	valString, _, err := key.GetStringValue(subKey)
	if err == nil {
		return valString, nil
	}
	valStrings, _, err := key.GetStringsValue(subKey)
	if err == nil {
		return strings.Join(valStrings, "\n"), nil
	}
	valBinary, _, err := key.GetBinaryValue(subKey)
	if err == nil {
		return string(valBinary), nil
	}
	valInteger, _, err := key.GetIntegerValue(subKey)
	if err == nil {
		return strconv.FormatUint(valInteger, 10), nil
	}

	return "", errors.New("Can't get type for sub key " + subKey)
}
