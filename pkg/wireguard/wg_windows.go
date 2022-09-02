package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

type WireguardWindows struct {
	Wgname string `def:"wg0"`
	Wgpath string `def:"wg0.conf"`
}

//start the wireguard tunnel
func (w WireguardWindows) CreateTunnelInterface() error {
	state, _ := w.GetInterfaceStatus(w.Wgname)
	//if already running, throw an error
	if state == 0 {
		return fmt.Errorf("interface already running for %s", w.Wgname)
	}
	args := []string{"/installtunnelservice", w.Wgpath}
	_, err := exec.Command("wireguard", args...).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w WireguardWindows) DeleteTunnelInterface(intfName string) error {

	state, _ := w.GetInterfaceStatus(intfName)
	//if already stopped, throw an error
	if state == 1 {
		return fmt.Errorf("interface already stopped for %s", intfName)
	}

	args := []string{"/uninstalltunnelservice", intfName}
	_, err := exec.Command("wireguard", args...).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w WireguardWindows) GetInterfaceStatus(intfName string) (int, error) {

	//get all running interfaces
	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Print(err)
		os.Exit(0)
	}
	for _, i := range interfaces {
		if i.Name == intfName {
			return 0, err
		}
	}
	return 1, err
}
