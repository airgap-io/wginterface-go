//go:build wireguard
// +build wireguard

package wireguard

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"airgap.io/wginterface/pkg/wireguard"
	"golang.org/x/sys/windows"
)

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("admin no")
		return false
	}
	fmt.Println("admin yes")
	return true
}
func (w *WgProp) CreateTunnelInterface() error {
	state, _ := w.GetInterfaceStatus(w.Wgname)
	if state == 0 {
		return fmt.Errorf("Interface already running for %s", w.Wgname)
	}
	if !amAdmin() {
		runMeElevated()
	}
	args := []string{"/installtunnelservice", w.Wgpath}
	_, err := exec.Command("wireguard", args...).Output()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	return err
}

func (w *WgProp) DeleteTunnelInterface(intfName string) error {

	state, _ := w.GetInterfaceStatus(intfName)
	if state == 1 {
		return fmt.Errorf("Interface already stopped for %s", intfName)
	}
	if !amAdmin() {
		runMeElevated()
	}
	args := []string{"/uninstalltunnelservice", intfName}
	_, err := exec.Command("wireguard", args...).Output()
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
