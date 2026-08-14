// Package registry builds a provider.Provider from a providers[] config entry.
//
// It exists so that adding a provider means adding an implementation and one
// line here, rather than editing the broker, the enrollment tool, and anything
// else that has to construct one. The map is built at compile time rather than
// through init()-time self-registration: a blank import that someone forgets
// would produce a broker that starts and then rejects every configured provider,
// which is a worse failure than a build error.
//
// It is a separate package from pkg/provider because the interface must not
// import its implementations — pkg/provider/github imports pkg/provider, so the
// factory cannot live there.
package registry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

// constructors maps providers[].type to its implementation. The key set must
// match config.SupportedProviderTypes, which is what Validate checks against so
// an unsupported type is a config error at startup rather than a failure halfway
// through construction; registry_test.go pins the two together.
var constructors = map[string]func(config.ProviderConfig) (provider.Provider, error){
	"github": func(c config.ProviderConfig) (provider.Provider, error) { return github.New(c) },
}

// New builds the provider described by cfg.
func New(cfg config.ProviderConfig) (provider.Provider, error) {
	ctor, ok := constructors[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("provider %q: type %q is not supported (supported: %s)",
			cfg.Name, cfg.Type, strings.Join(SupportedTypes(), ", "))
	}
	return ctor(cfg)
}

// NewAll builds every provider in cfg.Providers, in order. The first entry is
// the default when a request does not name one.
func NewAll(cfg *config.Config) ([]provider.Provider, error) {
	providers := make([]provider.Provider, 0, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		p, err := New(pc)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// SupportedTypes returns the registered provider types, sorted.
func SupportedTypes() []string {
	types := make([]string, 0, len(constructors))
	for t := range constructors {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}
