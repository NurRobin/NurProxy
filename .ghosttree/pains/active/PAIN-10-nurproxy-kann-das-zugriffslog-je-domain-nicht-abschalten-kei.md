# PAIN-10 NurProxy kann das Zugriffslog je Domain nicht abschalten (kein access_log off im nginx-Generator)

github.com/nurrobin/nurproxy | active

Befund beim Bau des Kunden-nginx (REQ-511, HowToSell, Zweig feat/kunden-nginx), Code gelesen auf NurProxy 61e8f96: internal/shared/nginxgen/generate.go Render erzeugt je Domain einen optionalen :80-Block mit return 301 und einen Hauptblock mit Zertifikatspfaden, optional limit_req, add_header aus CustomResponseHeaders und einem location / mit proxy_pass und proxy_set_header Host, X-Real-IP, X-Forwarded-For, X-Forwarded-Proto. Eine access_log-Zeile gibt es in keinem der beiden Blöcke. Die Domains erben daher access_log /var/log/nginx/access.log main_cf aus dem Host-nginx.conf: volle Client-IP (über CF-Connecting-IP), kein Host, 52 Tage Aufbewahrung. Weder models.ProxyConfig noch proxymodel.Route haben ein Feld dafür, die Capability-Liste kennt es nicht. Das Roh-Konfig-Feld (raw_config, Backend nginx) ersetzt zwar den ganzen Block und könnte access_log off; enthalten, verlangt aber handgeschriebene ssl_certificate-Pfade aus dem Zertifikatsspeicher des Agenten und bricht bei jeder Änderung des Speichers: nicht tragbar. Folge: Kundendomains (Besucherdaten, Datenschutzerklärung nennt gekürzte IP und 7 Tage) dürfen heute nicht über NurProxy veröffentlicht werden; pw deploy --via nurproxy ist gesperrt (pw_deploy.NURPROXY_CAN_DISABLE_ACCESS_LOG = False, nur Test- und Eigendomains mit --allow-edge-log), Kundendomains gehen über den certbot-Weg. Auch Fehler des Rands mit Client-IP (connect() failed zum Upstream) landen im gemeinsamen error.log; beim certbot-Weg dämpft error_log crit je vHost das, bei NurProxy-Domains nicht.

## Motivates

- https://github.com/NurRobin/NurProxy/pull/162

---
Projection from ghosttree. Edits to this file are lost on the next write.
