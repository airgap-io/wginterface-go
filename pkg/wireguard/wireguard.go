package wireguard

type Wireguard interface {
	CreateTunnelInterface() error
	DeleteTunnelInterface(intfName string) error
	// ConfigureInterface(intfName string, configPath string) error
	// AssignIpInterface(intfName string, ipAddress string) error
	GetInterfaceStatus(intfName string) (int, error)
}
