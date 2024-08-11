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
	HandshakeBuffer int       `yaml:"handshake_buffer"`
	Debug           bool      `yaml:"debug"`
}

type Network struct {
	ListenAddress string `yaml:"listen_address"`
	RemotePort    int    `yaml:"remote_port"`
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
}
