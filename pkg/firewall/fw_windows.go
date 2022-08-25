package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type FireWallWindows struct {
	Name string
	//Group    string
	Action   string
	Protocol string
	Port     int
}

var airgapWinConf string = ""

//to add / remove inbound rule from firewall
func addOrRemovePolicy(command string) (bool, error) {
	_, err := exec.Command("powershell", command).Output()
	if err != nil {
		return false, err
	}
	return true, err
}

//get the inblund rule from the command of airgap.conf
func getRuleNameFromCommand(command string) (string, error) {
	name := "name="
	dir := " dir="
	i1 := strings.Index(command, name)
	i2 := strings.Index(command, dir)
	if i2 > i1 {
		inputFmt := command[i1+len(name)+1 : i2-1]
		return inputFmt, exec.ErrNotFound
	}
	return "", fmt.Errorf("policy name not found in command")
}

//to copy the inbound rules in file(airgap.conf)
func setAirgapConfPath() bool {
	for _, element := range os.Environ() {
		variable := strings.Split(element, "=")
		if variable[0] == "ProgramFiles" {
			airgapWinConf = variable[1] + "\\Airgap\\airgap.conf"
			return true
		}
	}
	return false
}

//to add a new inbound rule in airgap.conf file
func (f *FireWallWindows) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	if !setAirgapConfPath() {
		return fmt.Errorf("environment variable - ProgramFiles is not present")
	}
	var command [2]string

	//build array of 2 strings
	if action == "allow" {
		command[0] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
		command[1] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	} else {
		command[0] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
		command[1] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	}
	//if file does not exists create a new file in given path
	if _, err := os.Stat(airgapWinConf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile(airgapWinConf)
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	//if command[1] is already added, we need to remove to add command[0]
	if existenceOfPolicy(airgapWinConf, command[1]) {
		b, _ := addOrRemovePolicy(command[1])
		if b {
			removeAPolicy(airgapWinConf, command[1])
		}
	}
	// check for the existence of command[0], to append a inbound rule
	if !existenceOfPolicy(airgapWinConf, command[0]) {
		b, err := addOrRemovePolicy(command[0])
		if b {
			appendAPolicy(airgapWinConf, command[0])
		} else {
			return err
		}
		return exec.ErrNotFound
	}
	return fmt.Errorf("command is already present")
}

//to check a status of a given inbound rule
func (f *FireWallWindows) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	if !setAirgapConfPath() {
		return false, fmt.Errorf("environment variable - ProgramFiles is not present")
	}
	//generate the command to check the status
	command := "netsh advfirewall firewall show rule name=" + "\"" + name + "\""
	_, err := exec.Command("powershell", command).Output()
	if err != nil {
		return false, err
	}
	return true, exec.ErrNotFound
}

//to delete a inbound rule
func (f *FireWallWindows) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	if !setAirgapConfPath() {
		return false, fmt.Errorf("environment variable - ProgramFiles is not present")
	}
	var command string = ""
	//build a command for allow or block
	if action == "allow" {
		command = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	} else {
		command = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	}
	//check and remove, if inbound rule exists
	if existenceOfPolicy(airgapWinConf, command) {
		commanddel := "netsh advfirewall firewall delete rule name=" + "\"" + f.Name + "\""
		b, err := addOrRemovePolicy(commanddel)
		if b {
			removeAPolicy(airgapWinConf, command)
			return true, exec.ErrNotFound
		} else {
			return false, err
		}
	}
	return false, fmt.Errorf("command not found in file")
}

//to delete all inbound rules
func (f *FireWallWindows) FlushNetworkPolicies() (bool, error) {
	ret := false
	if !setAirgapConfPath() {
		return ret, fmt.Errorf("environment variable - ProgramFiles is not present")
	}
	//read and get the existing inbound rules from airgap.conf
	strArr := readFile(airgapWinConf)

	err := fmt.Errorf("all Policies are removed")
	for _, command := range strArr {
		//get the rule name from command
		rulename, _ := getRuleNameFromCommand(command)
		if len(rulename) == 0 {
			continue
		}
		//generate command to delete a inbound rule
		commanddel := "netsh advfirewall firewall delete rule name=" + "\"" + rulename + "\""
		// remove a rule from firewall
		b, _ := addOrRemovePolicy(commanddel)
		if b {
			ret = true
			//remove a rule from file
			removeAPolicy(airgapWinConf, command)
		} else {
			err = fmt.Errorf("some commands could not be removed")
		}
	}
	return ret, err
}
