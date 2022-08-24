package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

type FireWallMac struct {
	Name string
	//Group    string
	Action   string
	Protocol string
	Port     int
}

var airgapMacConf string = "/etc/airgap.conf"
var pfConf string = "/etc/pf.conf"

func reloadFirewall() error {
	command := pfConf
	fmt.Println(command)
	_, err := exec.Command("sudo", "pfctl", "-f", command).Output()
	if err != nil {
		return fmt.Errorf("reload firewall error : %w", err)
	}
	return exec.ErrNotFound
}

func (f *FireWallMac) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	var command [2]string
	if action == "allow" {
		command[0] = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
		command[1] = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command[0] = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
		command[1] = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}

	if _, err := os.Stat(airgapMacConf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile(airgapMacConf)
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	if existenceOfPolicy(airgapMacConf, command[1]) {
		removeAPolicy(airgapMacConf, command[1])
	}
	if !existenceOfPolicy(airgapMacConf, command[0]) {
		appendAPolicy(airgapMacConf, command[0])
		err := reloadFirewall()
		if err != nil {
			return err
		}
		return exec.ErrNotFound
	}
	return fmt.Errorf("command is already present")
}
func (f *FireWallMac) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	var command string = ""
	if action == "allow" {
		//pass in quick proto tcp to any port 5354
		command = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}
	if existenceOfPolicy(airgapMacConf, command) {
		return true, exec.ErrNotFound
	}
	return false, exec.ErrNotFound
}

func (f *FireWallMac) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	var command string = ""
	if action == "allow" {
		command = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}
	if existenceOfPolicy(airgapMacConf, command) {
		b, err := removeAPolicy(airgapMacConf, command)
		if b {
			reloadFirewall()
			return true, exec.ErrNotFound
		} else {
			return false, err
		}
	}
	return false, fmt.Errorf("command not found in file")
}

func (f *FireWallMac) FlushNetworkPolicies() (bool, error) {
	b, err := removeAllAirgapPolicies(airgapMacConf)
	if b {
		return b, reloadFirewall()
	}
	return b, err
}
