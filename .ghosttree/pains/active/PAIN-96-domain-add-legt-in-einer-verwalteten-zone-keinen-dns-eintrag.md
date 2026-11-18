# PAIN-96 domain add legt in einer verwalteten Zone keinen DNS-Eintrag an und endet ohne Begründung in „degraded“

github.com/nurrobin/nurproxy | active

Am 2026-11-18 wurde `vault-nurproxy domain add --subdomain downloads --zone 07f52b60-… (deadweightlabs.com) --server b0049b82-… (orax) --port 3030` aufgerufen.

- Die Domain 104 kam mit dns_managed=false zurück. Nach dem ersten Sync stand sie auf status=degraded.
- Bei Cloudflare existierte kein Eintrag für downloads.deadweightlabs.com. Die anderen Domains derselben Zone und desselben Servers (designs, ghosttree, www, hooks) stehen auf dns_managed=true und haben einen CNAME auf orax.nurrobin.de.
- Warum die Domain degraded war, war nirgends zu sehen: Die CLI zeigt keinen Grund, und GET /api/v1/domains/104/events gibt 404.
- Behoben wurde es von Hand: CNAME downloads → orax.nurrobin.de bei Cloudflare angelegt, dann `domain dns-takeover 104`. Danach wurde der Status active, und das Zertifikat wurde ausgestellt. dns_managed steht trotzdem weiter auf false.

Erwartet wäre: Beim Anlegen in einer Zone, die NurProxy verwaltet, entsteht der DNS-Eintrag von selbst wie bei den anderen Domains. Ist ein Eintrag degraded, nennen CLI und API den Grund.

---
Projection from ghosttree. Edits to this file are lost on the next write.
