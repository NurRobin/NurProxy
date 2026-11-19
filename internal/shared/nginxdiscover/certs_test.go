package nginxdiscover

import (
	"reflect"
	"testing"
)

func TestCertRefs(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want []CertRef
	}{
		{
			name: "one server",
			conf: `server {
	listen 443 ssl;
	server_name app.example.com;
	ssl_certificate /etc/letsencrypt/live/app.example.com/fullchain.pem; # managed by Certbot
	ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
}`,
			want: []CertRef{{"/etc/letsencrypt/live/app.example.com/fullchain.pem", "/etc/letsencrypt/live/app.example.com/privkey.pem"}},
		},
		{
			name: "key inherited from http",
			conf: `http {
	ssl_certificate_key /etc/ssl/shared.key;
	server { ssl_certificate /etc/ssl/a.pem; }
	server { ssl_certificate "/etc/ssl/b.pem"; }
}`,
			want: []CertRef{{"/etc/ssl/a.pem", "/etc/ssl/shared.key"}, {"/etc/ssl/b.pem", "/etc/ssl/shared.key"}},
		},
		{
			name: "rsa and ecdsa pair in order",
			conf: `server {
	ssl_certificate /etc/ssl/rsa.pem; ssl_certificate_key /etc/ssl/rsa.key;
	ssl_certificate /etc/ssl/ec.pem; ssl_certificate_key /etc/ssl/ec.key;
}`,
			want: []CertRef{{"/etc/ssl/rsa.pem", "/etc/ssl/rsa.key"}, {"/etc/ssl/ec.pem", "/etc/ssl/ec.key"}},
		},
		{
			name: "relative path resolved against the prefix, duplicates once",
			conf: `server { ssl_certificate ssl/site.crt; ssl_certificate_key ssl/site.key; }
server { ssl_certificate ssl/site.crt; ssl_certificate_key ssl/site.key; }`,
			want: []CertRef{{"/etc/nginx/ssl/site.crt", "/etc/nginx/ssl/site.key"}},
		},
		{
			name: "variables and data: are skipped",
			conf: `server { ssl_certificate /etc/ssl/$ssl_server_name.crt; ssl_certificate_key /etc/ssl/$ssl_server_name.key; }
server { ssl_certificate data:$cert; ssl_certificate_key data:$key; }`,
		},
		{
			name: "commented out",
			conf: `server {
	# ssl_certificate /etc/ssl/old.pem;
	# ssl_certificate_key /etc/ssl/old.key;
}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CertRefs(tc.conf, "/etc/nginx")
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("CertRefs = %+v, want %+v", got, tc.want)
			}
		})
	}
}
