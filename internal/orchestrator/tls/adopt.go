package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NurRobin/NurProxy/internal/shared/models"
)

// AdoptionGrace is how long first issuance for a new central-TLS domain waits
// while its serving agent reports an adoptable certificate on disk (#80). It
// gives the operator time to adopt that certificate before NurProxy orders a
// duplicate from the CA; afterwards issuance proceeds as usual.
const AdoptionGrace = time.Hour

// NamesCover reports whether a certificate for names serves host. A wildcard
// name covers exactly one label, as in TLS hostname verification.
func NamesCover(names []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if n == host {
			return true
		}
		if rest, ok := strings.CutPrefix(n, "*."); ok {
			if i := strings.IndexByte(host, '.'); i > 0 && host[i+1:] == rest {
				return true
			}
		}
	}
	return false
}

// AdoptableFor reports whether a certificate an agent discovered on disk can
// be adopted for host at now, and why not otherwise. A certificate already in
// the renew window is refused: central renewal would replace it on the next
// scan, so adopting it would not save an ACME order.
func AdoptableFor(dc models.DiscoveredCert, host string, now time.Time) (bool, string) {
	switch {
	case dc.Fingerprint == "":
		return false, dc.Error
	case dc.Error != "":
		return false, dc.Error
	case !NamesCover(dc.Names, host):
		return false, fmt.Sprintf("certificate does not cover %s", host)
	case now.Before(dc.NotBefore):
		return false, "certificate is not valid yet"
	case !now.Before(dc.NotAfter):
		return false, "certificate expired"
	case !now.Before(dc.NotAfter.Add(-DefaultRenewWindow)):
		return false, "certificate expires within the renew window; ACME renewal would replace it at once"
	}
	return true, ""
}

// LeafFingerprint returns the lowercase hex SHA-256 of the first certificate
// in a PEM bundle, the identity agents report discovered certificates by.
func LeafFingerprint(certPEM string) (string, error) {
	rest := []byte(certPEM)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", errors.New("no PEM certificate found")
		}
		if block.Type == "CERTIFICATE" {
			sum := sha256.Sum256(block.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
}
