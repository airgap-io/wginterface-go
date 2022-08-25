package wireguard

// interface functions to start/stop/checkstatus of wireguard
type Wireguard interface {
	CreateTunnelInterface() error
	DeleteTunnelInterface(intfName string) error
	GetInterfaceStatus(intfName string) (int, error)
}
