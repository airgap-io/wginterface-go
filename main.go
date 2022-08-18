package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"airgap.io/wginterface/pkg/osquery"
	"airgap.io/wginterface/pkg/wireguard"
	_ "airgap.io/wginterface/pkg/wireguard"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("less input arguements")
		return
	}
	intfName := strings.Split(filepath.Base(os.Args[1]), ".")
	osName := osquery.DetectOS()
	if len(intfName[0]) > 0 {
		var wg wireguard.Wireguard
		if osName == "windows" {
			wgWindows := wireguard.WireguardWindows{}
			wgWindows.Wgname = intfName[0]
			wgWindows.Wgpath = os.Args[1]
			wg = wgWindows
		} else if osName == "darwin" {
			wgMac := wireguard.WireguardMac{}
			wgMac.Wgname = intfName[0]
			wgMac.Wgpath = os.Args[1]
			wg = wgMac
		}
		wg.CreateTunnelInterface()
		state, _ := wg.GetInterfaceStatus(intfName[0])
		fmt.Println(state)
		wg.DeleteTunnelInterface(intfName[0])
	}
}
