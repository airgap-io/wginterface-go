package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"airgap.io/wginterface/pkg/firewall"
	"airgap.io/wginterface/pkg/osquery"
	"airgap.io/wginterface/pkg/wireguard"
	_ "airgap.io/wginterface/pkg/wireguard"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("less input arguements")
		return
	}

	osName := osquery.DetectOS()
	//firewall
	if osName == "windows" {
		fw := firewall.FireWallWindows{}
		fw.Name = os.Args[1]
		fw.Action = os.Args[2]
		fw.Protocol = os.Args[3]
		fw.Port, _ = strconv.Atoi(os.Args[4])
		fw.AddNetworkPolicy(fw.Name, fw.Action, fw.Protocol, fw.Port)
		time.Sleep(10 * time.Second)
		b, _ := fw.CheckRuleStatus(fw.Name)
		fmt.Println("status", b)
		b, _ = fw.DeleteNetworkPolicy(fw.Name)
		fmt.Println("delete", b)

	}
	//wireguard
	{
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

}
