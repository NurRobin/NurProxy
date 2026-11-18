# PAIN-95 domain update --force-https meldet „updated“, aber force_https bleibt false

github.com/nurrobin/nurproxy | active

Am 2026-11-18 sollte für downloads.deadweightlabs.com (Domain-ID 104, Server orax) die Weiterleitung von HTTP auf HTTPS eingeschaltet werden. Benutzt wurde der deployte CLI v0.4.0-dev-61e8f96 über vault-nurproxy.

- `vault-nurproxy domain update 104 --force-https` meldet „domain updated: 104“, mit `--json` kam kein auswertbares JSON zurück.
- `vault-nurproxy domain update 104 --force-https=true` meldet ebenfalls „domain updated: 104“.
- Danach liefert `domain list --json` für 104 weiter force_https=false, auch nach über zwei Minuten und mit status=active.
- Die erzeugte nginx-Datei /etc/nginx/sites-available/nurproxy-downloads.deadweightlabs.com.conf hat keinen server-Block für Port 80; http://downloads.deadweightlabs.com/ antwortet gar nicht.

Schon `domain add` ohne --force-https hat force_https=false gesetzt. Die übrigen Domains derselben Zone (designs, ghosttree, www) stehen auf true. Wer die Option beim Anlegen vergisst, kann sie nachträglich nicht setzen.

---
Projection from ghosttree. Edits to this file are lost on the next write.
