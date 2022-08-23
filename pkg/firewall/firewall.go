package firewall

type Firewall interface {
	AddNetworkPolicy(name string, action string, protocol string, port int) error
	DeleteNetworkPolicy(name string, action string, protocol string, port int) (bool, error)
	CheckRuleStatus(name string, action string, protocol string, port int) (bool, error)
}
