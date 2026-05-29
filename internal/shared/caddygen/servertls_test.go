package caddygen

import (
	"reflect"
	"testing"

	"github.com/NurRobin/NurProxy/internal/shared/proxymodel"
)

func TestGenerateServerTLS(t *testing.T) {
	tests := []struct {
		name  string
		hosts []TLSHost
		want  ServerTLS
	}{
		{
			name:  "no hosts disables automatic https",
			hosts: nil,
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "single provided cert host loads file and disables acme",
			hosts: []TLSHost{
				{Host: "app.example.com", Policy: proxymodel.TLSPolicyCentral, CertPath: "/c/app.crt", KeyPath: "/c/app.key"},
			},
			want: ServerTLS{
				LoadFiles: []LoadFile{
					{Certificate: "/c/app.crt", Key: "/c/app.key"},
				},
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "empty policy defaults to central provided cert",
			hosts: []TLSHost{
				{Host: "app.example.com", CertPath: "/c/app.crt", KeyPath: "/c/app.key"},
			},
			want: ServerTLS{
				LoadFiles: []LoadFile{
					{Certificate: "/c/app.crt", Key: "/c/app.key"},
				},
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "multiple provided certs sorted and acme disabled",
			hosts: []TLSHost{
				{Host: "b.example.com", Policy: proxymodel.TLSPolicyCentral, CertPath: "/c/b.crt", KeyPath: "/c/b.key"},
				{Host: "a.example.com", Policy: proxymodel.TLSPolicyCentral, CertPath: "/c/a.crt", KeyPath: "/c/a.key"},
			},
			want: ServerTLS{
				LoadFiles: []LoadFile{
					{Certificate: "/c/a.crt", Key: "/c/a.key"},
					{Certificate: "/c/b.crt", Key: "/c/b.key"},
				},
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "single self-acme host keeps automatic https on with no skip",
			hosts: []TLSHost{
				{Host: "app.example.com", Policy: proxymodel.TLSPolicySelfACME},
			},
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{},
			},
		},
		{
			name: "mixed: provided host skipped, self-acme host managed",
			hosts: []TLSHost{
				{Host: "provided.example.com", Policy: proxymodel.TLSPolicyCentral, CertPath: "/c/p.crt", KeyPath: "/c/p.key"},
				{Host: "acme.example.com", Policy: proxymodel.TLSPolicySelfACME},
			},
			want: ServerTLS{
				LoadFiles: []LoadFile{
					{Certificate: "/c/p.crt", Key: "/c/p.key"},
				},
				AutomaticHTTPS: AutomaticHTTPS{Skip: []string{"provided.example.com"}},
			},
		},
		{
			name: "off host is skipped from acme and loads no cert",
			hosts: []TLSHost{
				{Host: "plain.example.com", Policy: proxymodel.TLSPolicyOff},
			},
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "off host coexisting with self-acme is skipped not disabled",
			hosts: []TLSHost{
				{Host: "plain.example.com", Policy: proxymodel.TLSPolicyOff},
				{Host: "acme.example.com", Policy: proxymodel.TLSPolicySelfACME},
			},
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{Skip: []string{"plain.example.com"}},
			},
		},
		{
			name: "provided host without cert paths still skips acme but loads nothing",
			hosts: []TLSHost{
				{Host: "app.example.com", Policy: proxymodel.TLSPolicyCentral},
			},
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
		{
			name: "blank host is ignored",
			hosts: []TLSHost{
				{Host: "", Policy: proxymodel.TLSPolicyCentral, CertPath: "/c/x.crt", KeyPath: "/c/x.key"},
			},
			want: ServerTLS{
				AutomaticHTTPS: AutomaticHTTPS{Disable: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateServerTLS(tt.hosts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateServerTLS()\n got = %+v\nwant = %+v", got, tt.want)
			}
		})
	}
}
