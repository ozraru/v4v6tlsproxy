package internal

import (
	"log"
	"net/netip"
	"os"
	"regexp"

	"github.com/goccy/go-yaml"
)

type Set[T comparable] map[T]struct{}

func (s *Set[T]) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var list []T
	if err := unmarshal(&list); err != nil {
		return err
	}
	*s = make(Set[T], len(list))
	for _, v := range list {
		(*s)[v] = struct{}{}
	}
	return nil
}

type ConfigStruct struct {
	Network         Network   `yaml:"network"`
	AllowRule       AllowRule `yaml:"allow_rule"`
	DenyRule        DenyRule  `yaml:"deny_rule"`
	HandshakeBuffer int       `yaml:"handshake_buffer"`
	Debug           bool      `yaml:"debug"`
}

type Network struct {
	ListenAddress        string     `yaml:"listen_address"`
	DialSourceAddress    netip.Addr `yaml:"-"`
	DialSourceAddressRaw string     `yaml:"dial_source_address"`
	UseAddressConversion bool       `yaml:"use_address_conversion"`
	RemotePort           int        `yaml:"remote_port"`
}

type AllowRule struct {
	IPv4Addr        []netip.Prefix  `yaml:"-"`
	IPv4AddrRaw     []string        `yaml:"ipv4_addr"`
	DomainWhitelist DomainWhitelist `yaml:"domain"`
}

type DomainWhitelist struct {
	Plain    Set[string]      `yaml:"plain"`
	Regex    []*regexp.Regexp `yaml:"-"`
	RegexRaw []string         `yaml:"regex"`
}

type DenyRule struct {
	IPv6Addr    []netip.Prefix `yaml:"-"`
	IPv6AddrRaw []string       `yaml:"ipv6_addr"`
}

var Config ConfigStruct

func init() {
	f, err := os.Open("config.yaml")
	if err != nil {
		log.Fatal("Failed to open config.yaml: ", err)
	}
	err = yaml.NewDecoder(f).Decode(&Config)
	if err != nil {
		log.Fatal("Failed to decode config.yaml: ", err)
	}

	if Config.Network.DialSourceAddressRaw != "" {
		Config.Network.DialSourceAddress = netip.MustParseAddr(Config.Network.DialSourceAddressRaw)
		if !Config.Network.DialSourceAddress.Is6() {
			log.Fatal("dial source address must be ipv6 address")
		}
	}

	if Config.Network.UseAddressConversion {
		if !Config.Network.DialSourceAddress.IsValid() {
			log.Fatal("To use address conversion, require valid prefix")
		}
		addr := Config.Network.DialSourceAddress.As16()
		if addr[12] != 0 || addr[13] != 0 || addr[14] != 0 || addr[15] != 0 {
			log.Fatal("To use address conversion, last 32 bits of dial source address must be zero")
		}
	}

	Config.AllowRule.IPv4Addr = make([]netip.Prefix, len(Config.AllowRule.IPv4AddrRaw))
	for i, v := range Config.AllowRule.IPv4AddrRaw {
		Config.AllowRule.IPv4Addr[i] = netip.MustParsePrefix(v)
	}

	Config.AllowRule.DomainWhitelist.Regex = make([]*regexp.Regexp, len(Config.AllowRule.DomainWhitelist.RegexRaw))
	for i, v := range Config.AllowRule.DomainWhitelist.RegexRaw {
		r, err := regexp.Compile(v)
		if err != nil {
			log.Fatal("Failed to compile regex: ", err)
		}
		Config.AllowRule.DomainWhitelist.Regex[i] = r
	}

	Config.DenyRule.IPv6Addr = make([]netip.Prefix, len(Config.DenyRule.IPv6AddrRaw))
	for i, v := range Config.DenyRule.IPv6AddrRaw {
		Config.DenyRule.IPv6Addr[i] = netip.MustParsePrefix(v)
	}
}
