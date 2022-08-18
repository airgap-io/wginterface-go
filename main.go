package main

import (
	"fmt"
	"os"
	"path/filepath"
	_ "path/filepath"
	"strings"

	"airgap.io/wginterface/pkg/osquery"
	"airgap.io/wginterface/pkg/wireguard"
	_ "airgap.io/wginterface/pkg/wireguard"
)

type WgProp struct {
	Wgname string `def:"wg0"`
	Wgpath string `def:"ooo"`
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("less input arguements")
		return
	}
	intfName := strings.Split(filepath.Base(os.Args[1]), ".")
	osName := osquery.DetectOS()
	if len(intfName) > 0 {
		if osName == "windows" {
			var wg wireguard.Wireguard
			wg = &wireguard.WgProp{"a", "b"}
			wg.CreateTunnelInterface()
			//wgObj.InitializeWireguardInstance(intfName[0], os.Args[1])
			//wgObj.CreateTunnelInterface()
			//wgObj := wireguard.WgName{wgname: intfName[0], wgpath: os.Args[1]}
			// wgObj := &wireguard.WgName{
			// 	wgname: "ww",
			// 	wgpath: "Anton",
			// }
			//e1 := Event{Id: 1, Name: "event 1"}
			// err := wgObj.CreateTunnelInterface()
			// if err != nil {
			// 	fmt.Println(err)
			// }
			// err = wgObj.DeleteTunnelInterface(intfName[0])
			// if err != nil {
			// 	fmt.Println(err)
			// }
		} // else if osName == "darwin" {
		// 	wgObj := new wireguard()
		// 	err := wgObj.CreateTunnelInterface()
		// 	if err != nil {
		// 		fmt.Println(err)
		// 	}
		// 	err = wgObj.DeleteTunnelInterface(intfName[0])
		// 	if err != nil {
		// 		fmt.Println(err)
		// 	} else {
		// 		fmt.Println("OS : ", runtime.GOOS)
		// 	}
		// }
	}
}
