package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// LEDirectoryProduction and LEStaging mirror lego's directory URLs so callers can
// pick the CA without importing lego.
const (
	LEDirectoryProduction = lego.LEDirectoryProduction
	LEDirectoryStaging    = lego.LEDirectoryStaging
)

// LegoConfig configures the real lego-backed ACMEClient.
type LegoConfig struct {
	// Email is the ACME account contact address.
	Email string
	// CADirURL is the ACME directory endpoint; defaults to LE production.
	CADirURL string
	// AccountKey is the ACME account private key. Generated if nil.
	AccountKey crypto.PrivateKey
}

// legoUser adapts an account into lego's registration.User.
type legoUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// legoClient is the production ACMEClient: it drives lego with our providerSolver
// wired as the DNS-01 challenge provider. It is intentionally thin and is not
// unit-tested with real network; the orchestration around it is exercised through
// the ACMEClient seam with a hand-written fake.
type legoClient struct {
	cfg LegoConfig
}

// NewLegoClient builds an ACMEClient backed by lego. The account key is
// generated if not supplied (callers should persist it for renewal continuity).
func NewLegoClient(cfg LegoConfig) (ACMEClient, error) {
	if cfg.CADirURL == "" {
		cfg.CADirURL = LEDirectoryProduction
	}
	if cfg.AccountKey == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("tls: generating ACME account key: %w", err)
		}
		cfg.AccountKey = key
	}
	return &legoClient{cfg: cfg}, nil
}

// legoChallengeProvider adapts providerSolver to lego's challenge.Provider.
type legoChallengeProvider struct {
	solver *providerSolver
}

func (p legoChallengeProvider) Present(domain, token, keyAuth string) error {
	return p.solver.legoPresent(domain, token, keyAuth)
}

func (p legoChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	return p.solver.legoCleanUp(domain, token, keyAuth)
}

func (c *legoClient) ObtainViaDNS01(ctx context.Context, names []string, solver DNSSolver) (*CertResult, error) {
	ps, ok := solver.(*providerSolver)
	if !ok {
		return nil, errors.New("tls: lego client requires the provider-backed solver")
	}
	if len(names) == 0 {
		return nil, errors.New("tls: no names to issue")
	}

	user := &legoUser{email: c.cfg.Email, key: c.cfg.AccountKey}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = c.cfg.CADirURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("tls: creating ACME client: %w", err)
	}

	if err := client.Challenge.SetDNS01Provider(legoChallengeProvider{solver: ps}); err != nil {
		return nil, fmt.Errorf("tls: setting DNS-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("tls: registering ACME account: %w", err)
	}
	user.registration = reg

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: names,
		Bundle:  true,
	})
	if err != nil {
		return nil, err
	}

	return &CertResult{
		Host:    names[0],
		Names:   names,
		CertPEM: res.Certificate,
		KeyPEM:  res.PrivateKey,
	}, nil
}
