package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
)

type FireWallWindows struct {
	Name string
	//Group    string
	Action   string
	Protocol string
	Port     int
}

func (f *FireWallWindows) AddNetworkPolicy(name string, action string, protocol string, port int) error {
	arguement := "netsh advfirewall firewall add rule name=" + "\"" + f.Name + "\"" + " dir=in action=" + action + " protocol=" + f.Protocol + " localport=" + strconv.Itoa(f.Port)
	_, err := exec.Command("powershell", arguement).Output()
	if err != nil {
		fmt.Println("AddNetworkPolicy Error: ", err)
	}
	return err
}

func (f *FireWallWindows) CheckRuleStatus(name string, action string, protocol string, port int) (bool, error) {
	arguement := "netsh advfirewall firewall show rule name=" + "\"" + name + "\""
	fmt.Println(arguement)
	_, err := exec.Command("powershell", arguement).Output()
	if err != nil {
		//fmt.Println("RuleStatus Error: ", err)
		return false, err
	}
	return true, exec.ErrNotFound
}
func (f *FireWallWindows) DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error) {
	arguement := "netsh advfirewall firewall delete rule name=" + "\"" + name + "\""
	fmt.Println(arguement)
	cmd, err := exec.Command("powershell", arguement).Output()
	fmt.Println(cmd)
	if err != nil {
		fmt.Println("DeleteNetworkPolicy Error: ", err)
		return false, err
	}
	return true, exec.ErrNotFound
}
