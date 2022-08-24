package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Firewall interface {
	AddNetworkPolicy(name string, action string, protocol string, port int) error
	DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error)
	CheckRuleStatus(name string, action string, protocol string, port int) (bool, error)
	FlushNetworkPolicies() (bool, error)
}

func readFile(conffile string) []string {
	readFile, err := os.Open(conffile)
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

func existenceOfPolicy(conffile string, command string) bool {
	strArr := readFile(conffile)
	for _, str1 := range strArr {
		if strings.HasPrefix(str1, command) {
			return true
		}
	}
	return false
}

func createNewFile(conffile string) error {
	myfile, err := os.Create(conffile)
	if err != nil {
		return fmt.Errorf("run error: %w", err)
	}
	myfile.Close()
	return err
}
func appendAPolicy(conffile string, command string) error {
	f, err := os.OpenFile(conffile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return fmt.Errorf("run error: %w", err)
	}
	defer f.Close()
	_, err2 := f.WriteString(command)
	_, _ = f.WriteString("\n")
	if err2 != nil {
		return fmt.Errorf("run error: %w", err2)
	}
	return exec.ErrNotFound
}

func removeAPolicy(conffile string, command string) (bool, error) {
	f, err := os.Open(conffile)
	if err != nil {
		return false, fmt.Errorf("open file error: %w", err)
	}
	defer f.Close()

	var bs []byte
	buf := bytes.NewBuffer(bs)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), command) {
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

	err = os.WriteFile(conffile, buf.Bytes(), 0666)
	if err != nil {
		return false, fmt.Errorf("write file error: %w", err)
	}
	return true, exec.ErrNotFound
}

func removeAllAirgapPolicies(conffile string) (bool, error) {
	file, err := os.Open(conffile)
	if err != nil {
		return false, fmt.Errorf("open file error: %w", err)
	}
	defer file.Close()

	var bs []byte
	buf := bytes.NewBuffer(bs)
	var command [2]string
	command[0] = "pass in"
	command[1] = "block in"

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if !strings.HasPrefix(scanner.Text(), command[0]) && !strings.HasPrefix(scanner.Text(), command[1]) {
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

	err = os.WriteFile(conffile, buf.Bytes(), 0666)
	if err != nil {
		return false, fmt.Errorf("write file error: %w", err)
	}
	return true, exec.ErrNotFound
}
