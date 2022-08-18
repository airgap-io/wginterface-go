//go:build wireguard
// +build wireguard

package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
)

func (w *WgProp) CreateTunnelInterface() error {

	state, err := w.GetInterfaceStatus(w.Wgname)
	if state == 0 {
		return err
	}
	exePath := "wg-quick"
	_, err = exec.Command(exePath, "up", w.Wgname).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w *WgProp) DeleteTunnelInterface(intfName string) error {
	exePath := "wg-quick"
	_, err := exec.Command(exePath, "down", intfName).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w *WgProp) GetInterfaceStatus(intfName string) (int, error) {

	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Print(err)
		os.Exit(0)
	}
	for _, i := range interfaces {
		if i.Name == intfName {
			return 0, fmt.Errorf("Interface already running for %s", intfName)
		}
	}
	return 1, exec.ErrNotFound
}
