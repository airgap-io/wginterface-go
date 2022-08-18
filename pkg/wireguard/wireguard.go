package wireguard

type Wireguard interface {
	CreateTunnelInterface() error
	DeleteTunnelInterface(intfName string) error
	// ConfigureInterface(intfName string, configPath string) error
	// AssignIpInterface(intfName string, ipAddress string) error
	GetInterfaceStatus(intfName string) (int, error)
}

type WgProp struct {
	Wgname string `def:"wg0"`
	Wgpath string `def:"ooo"`
}

func New(wgname string, wgpath string) *WgProp {
	return &(WgProp{
		Wgname: wgname,
		Wgpath: wgpath,
	})
}
