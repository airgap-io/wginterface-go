package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type FireWallMac struct {
	Name string
	//Group    string
	Action   string
	Protocol string
	Port     int
}

var airgapconf string = "/etc/airgap.conf"
var pfconf string = "/etc/pf.conf"

func readFile() []string {
	readFile, err := os.Open(airgapconf)
	if err != nil {
		fmt.Println(err)
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	var s []string
	for fileScanner.Scan() {
		s = append(s, fileScanner.Text())
	}
	readFile.Close()
	return s
}

func existenceOfInBoundRule(command string) bool {
	strArr := readFile()
	for _, str1 := range strArr {
		if strings.Contains(str1, command) {
			return true
		}
	}
	return false
}

func createNewFile() error {
	myfile, err := os.Create(airgapconf)
	if err != nil {
		return fmt.Errorf("run error: %w", err)
	}
	myfile.Close()
	return err
}

func appendInBoundToFile(command string) error {
	f, err := os.OpenFile(airgapconf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return fmt.Errorf("run error: %w", err)
	}
	defer f.Close()
	_, err2 := f.WriteString(command)
	if err2 != nil {
		return fmt.Errorf("run error: %w", err2)
	}
	return exec.ErrNotFound
}

func removeInBoundFromFile(command string) (bool, error) {
	f, err := os.Open(airgapconf)
	if err != nil {
		return false, fmt.Errorf("open file error: %w", err)
	}
	defer f.Close()

	var bs []byte
	buf := bytes.NewBuffer(bs)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if !strings.Contains(scanner.Text(), command) {
			_, err := buf.Write(scanner.Bytes())
			if err != nil {
				return false, fmt.Errorf("scan text error: %w", err)
			}
			_, err = buf.WriteString("\n")
			if err != nil {
				return false, fmt.Errorf("write error: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan file error: %w", err)
	}

	err = os.WriteFile(airgapconf, buf.Bytes(), 0666)
	if err != nil {
		return false, fmt.Errorf("write file error: %w", err)
	}
	return true, exec.ErrNotFound
}

func reloadFirewall() error {
	command := pfconf
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

	if _, err := os.Stat(airgapconf); errors.Is(err, os.ErrNotExist) {
		err := createNewFile()
		if err != nil {
			return fmt.Errorf("airgap.conf file creation issue")
		}
	}
	if existenceOfInBoundRule(command[1]) {
		removeInBoundFromFile(command[1])
	}
	if !existenceOfInBoundRule(command[0]) {
		appendInBoundToFile(command[0])
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
	if existenceOfInBoundRule(command) {
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
	if existenceOfInBoundRule(command) {
		removeInBoundFromFile(command)
		reloadFirewall()
		return true, exec.ErrNotFound
	}
	return false, fmt.Errorf("command not found in file")
}
