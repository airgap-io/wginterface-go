package firewall

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
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

func addOrRemovePolicy(command string) (bool, error) {
	_, err := exec.Command("powershell", command).Output()
	if err != nil {
		return false, err
	}
	return true, err
}

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

func setAirgapConfPath() {
	u, _ := user.Current()
	airgapWinConf = u.HomeDir + "\\airgap\\airgap.conf"
}

func (f *FireWallWindows) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	setAirgapConfPath()
	var command [2]string
	if action == "allow" {
		command[0] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
		command[1] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	} else {
		command[0] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
		command[1] = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	}

	if _, err := os.Stat(airgapWinConf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile(airgapWinConf)
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	if existenceOfPolicy(airgapWinConf, command[1]) {
		b, _ := addOrRemovePolicy(command[1])
		if b {
			removeAPolicy(airgapWinConf, command[1])
		}
	}
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

func (f *FireWallWindows) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	setAirgapConfPath()
	command := "netsh advfirewall firewall show rule name=" + "\"" + name + "\""
	_, err := exec.Command("powershell", command).Output()
	if err != nil {
		return false, err
	}
	return true, exec.ErrNotFound
}

func (f *FireWallWindows) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	setAirgapConfPath()
	var command string = ""
	if action == "allow" {
		command = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	} else {
		command = "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + "block" + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	}
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

func (f *FireWallWindows) FlushNetworkPolicies() (bool, error) {
	setAirgapConfPath()
	strArr := readFile(airgapWinConf)
	ret := false
	err := fmt.Errorf("all Policies are removed")
	for _, command := range strArr {
		rulename, _ := getRuleNameFromCommand(command)
		if len(rulename) == 0 {
			continue
		}
		commanddel := "netsh advfirewall firewall delete rule name=" + "\"" + rulename + "\""
		b, _ := addOrRemovePolicy(commanddel)
		if b {
			ret = true
			removeAPolicy(airgapWinConf, command)
		} else {
			err = fmt.Errorf("some commands could not be removed")
		}
	}
	return ret, err
}
