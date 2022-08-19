package firewall

type Firewall interface {
	AddNetworkPolicy(name string, protocol string, port int) error
	DeleteNetworkPolicy(name string) (bool, error)
	CheckRuleStatus(name string) (bool, error)
}
