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

//common variables
var airgapMacConf string = "/Library/Application Support/Airgap/airgap.conf"
var pfConf string = "/etc/pf.conf"

//to reload the firewall
func reloadFirewall() error {
	command := pfConf
	_, err := exec.Command("sudo", "pfctl", "-f", command).Output()
	if err != nil {
		return fmt.Errorf("reload firewall error : %w", err)
	}
	return exec.ErrNotFound
}

//to add a new inbound rule in airgap.conf file
func (f *FireWallMac) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	var command [2]string

	//build array of 2 strings
	if action == "allow" {
		command[0] = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
		command[1] = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command[0] = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
		command[1] = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}
	//if file does not exists create a new file in given path
	if _, err := os.Stat(airgapMacConf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile(airgapMacConf)
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	//if command[1] is already added, we need to remove to add command[0]
	if existenceOfPolicy(airgapMacConf, command[1]) {
		removeAPolicy(airgapMacConf, command[1])
	}
	// check for the existence of command[0], to append a inbound rule
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

//to check a status of a given inbound rule
func (f *FireWallMac) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	var command string = ""
	//build a command for allow or block
	if action == "allow" {
		command = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}
	// check and return true, if inbound rule exists
	if existenceOfPolicy(airgapMacConf, command) {
		return true, exec.ErrNotFound
	}
	return false, exec.ErrNotFound
}

//to delete a inbound rule
func (f *FireWallMac) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	var command string = ""
	//build a command for allow or block
	if action == "allow" {
		command = "pass in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	} else {
		command = "block in quick proto " + protocol + " to any port " + strconv.Itoa(port)
	}
	//check and remove, if inbound rule exists
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

//to delete all inbound rules
func (f *FireWallMac) FlushNetworkPolicies() (bool, error) {
	//remove all inbound rules from airgap.conf
	b, err := removeAllAirgapPolicies(airgapMacConf)
	if b {
		//to get the impact of removed inbound rules
		return b, reloadFirewall()
	}
	return b, err
}
