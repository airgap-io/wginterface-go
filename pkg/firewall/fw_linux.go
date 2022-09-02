package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type FireWallLinux struct {
	Name string
	//Group    string
	Action   string
	Protocol string
	Port     int
}

//common variables
var airgapLinuxConf string = "/usr/lib/Airgap/airgap.conf"

//to add a new inbound rule in airgap.conf file
func (f *FireWallLinux) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	var command [2][]string
	//build array of 2 strings
	if action == "allow" {
		command[0] = generateInBoundRule(action, protocol, port, true)
		command[1] = generateInBoundRule("deny", protocol, port, true)
	} else {
		command[0] = generateInBoundRule("deny", protocol, port, true)
		command[1] = generateInBoundRule(action, protocol, port, true)
	}
	//if file does not exists create a new file in given path
	if _, err := os.Stat(airgapLinuxConf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile(airgapLinuxConf)
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	//if command[1] is already added, we need to remove to add command[0]
	if existenceOfPolicy(airgapLinuxConf, combineArrayOfStrings(command[1])) {

		b, err := addToOrDeleteRuleFromIPTables(command[1])
		if b {
			removeAPolicy(airgapLinuxConf, combineArrayOfStrings(command[1]))
		} else {
			return err
		}

	}
	// check for the existence of command[0], to append a inbound rule
	if !existenceOfPolicy(airgapLinuxConf, combineArrayOfStrings(command[0])) {
		b, err := addToOrDeleteRuleFromIPTables(command[0])
		if b {
			appendAPolicy(airgapLinuxConf, combineArrayOfStrings(command[0]))
		} else {
			return err
		}
		return exec.ErrNotFound
	}
	return fmt.Errorf("command is already present")
}

//to check a status of a given inbound rule
func (f *FireWallLinux) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	var command []string
	//build a command for allow or block
	if action == "allow" {
		command = generateInBoundRule(action, protocol, port, true)
	} else {
		command = generateInBoundRule("deny", protocol, port, true)
	}
	// check and return true, if inbound rule exists
	if existenceOfPolicy(airgapLinuxConf, combineArrayOfStrings(command)) {
		return true, exec.ErrNotFound
	}
	return false, exec.ErrNotFound
}

//to delete a inbound rule
func (f *FireWallLinux) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	//var command string = ""
	var command []string
	var delcommand []string
	//build a command for allow or block
	if action == "allow" {
		command = generateInBoundRule(action, protocol, port, true)
		delcommand = generateInBoundRule(action, protocol, port, false)
	} else {
		command = generateInBoundRule("deny", protocol, port, true)
		delcommand = generateInBoundRule("deny", protocol, port, false)
	}
	//check and remove, if inbound rule exists
	if existenceOfPolicy(airgapLinuxConf, combineArrayOfStrings(command)) {
		_, _ = removeAPolicy(airgapLinuxConf, combineArrayOfStrings(command))
		b, err := addToOrDeleteRuleFromIPTables(delcommand)
		if b {
			return true, exec.ErrNotFound
		} else {
			return false, err
		}
	}
	return false, fmt.Errorf("command not found in file")
}

//to delete all inbound rules
func (f *FireWallLinux) FlushNetworkPolicies() (bool, error) {

	strArr := readFile(airgapLinuxConf)
	err := fmt.Errorf("all policies removed")
	b2 := true
	for _, command := range strArr {
		delcommand := splitStrings(command)
		if len(delcommand) > 2 {
			// change the 1st pos to "-D" to delete rule from  iptables
			delcommand[1] = "-D"
		}
		b, _ := removeAPolicy(airgapLinuxConf, command)
		if b {
			b1, _ := addToOrDeleteRuleFromIPTables(delcommand)
			if !b1 {
				err = fmt.Errorf("some of the policies not removed")
				b2 = false
			}

		}
	}
	return b2, err
}

func addToOrDeleteRuleFromIPTables(command []string) (bool, error) {
	_, err := exec.Command("sudo", command...).Output()
	if err != nil {
		return false, fmt.Errorf("reload firewall error : %w", err)
	}
	return true, exec.ErrNotFound
}

func generateInBoundRule(action string, protocol string, port int, add bool) []string {
	var command []string
	if add {
		if action == "allow" {
			command = []string{"iptables", "-A", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
		} else {
			command = []string{"iptables", "-A", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "DROP"}
		}
	} else {
		if action == "allow" {
			command = []string{"iptables", "-D", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT"}
		} else {
			command = []string{"iptables", "-D", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "DROP"}
		}
	}
	return command
}

func combineArrayOfStrings(command []string) string {
	strCombine := strings.Join(command, " ")
	return strCombine
}

func splitStrings(str string) []string {
	return strings.Split(str, " ")
}
