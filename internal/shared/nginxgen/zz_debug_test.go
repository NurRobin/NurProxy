package nginxgen

import (
	"fmt"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestZZDebugRender(t *testing.T) {
	res, err := Render(Input{
		Route: proxymodel.Route{
			Host:      "grpc.sandbox.test",
			Upstream:  proxymodel.Upstream{Addr: "127.0.0.1", Port: 9090},
			TLS:       proxymodel.TLSConfig{Policy: proxymodel.TLSPolicyCentral},
		},
		CertPath:     "/var/lib/nurproxy-agent/certs/grpc.sandbox.test.crt",
		KeyPath:      "/var/lib/nurproxy-agent/certs/grpc.sandbox.test.key.plain",
		NginxVersion: "1.26.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("---PREAMBLE---")
	fmt.Println(res.HTTPPreamble)
	fmt.Println("---SERVER---")
	fmt.Println(res.Server)
}
