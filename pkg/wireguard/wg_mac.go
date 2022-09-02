package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

type WireguardMac struct {
	Wgname string `def:"wg0"`
	Wgpath string `def:"wg0.conf"`
}

func (w WireguardMac) CreateTunnelInterface() error {

	state, _ := w.GetInterfaceStatus(w.Wgname)
	if state == 0 {
		return fmt.Errorf("interface already running for %s", w.Wgname)
	}
	exePath := "wg-quick"
	_, err := exec.Command(exePath, "up", w.Wgname).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w WireguardMac) DeleteTunnelInterface(intfName string) error {
	state, _ := w.GetInterfaceStatus(intfName)
	if state == 1 {
		return fmt.Errorf("interface already stopped for %s", intfName)
	}
	exePath := "wg-quick"
	_, err := exec.Command(exePath, "down", intfName).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w WireguardMac) GetInterfaceStatus(intfName string) (int, error) {

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
