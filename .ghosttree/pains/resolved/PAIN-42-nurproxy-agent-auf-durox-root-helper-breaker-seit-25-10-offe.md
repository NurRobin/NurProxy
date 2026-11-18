# PAIN-42 NurProxy-Agent auf durox: Root-Helper-Breaker seit 25.10. offen, alle durox-Domains stehen auf error

github.com/nurrobin/nurproxy | resolved

Ausgelöst am 2026-10-25 22:36 (Ortszeit) durch das Verschieben der Domain 59 healthdata von durox nach orax (REQ-551). Der Full-Sync auf durox scheiterte mit "native proxy validation failed after managed commit", das Rollback blieb partial (rollback_failed), seitdem meldet der Agent alle ~70 s "persistent helper breaker is open". Alle durox-Domains (homeassistant, jellyfin, vault, smp-panel, ops, …) stehen im Orchestrator auf error; ausgeliefert werden sie weiter mit der zuletzt geladenen nginx-Konfiguration, nginx -t ist aktuell ok. Die alte vhost-Datei nurproxy-healthdata.nurrobin.de.conf liegt noch auf durox (harmlos, DNS zeigt auf orax). Änderungen an durox-Domains greifen bis zur manuellen Validierung (breaker.go: rollback_failed requires successful manual validation) nicht.

## Motivates

- https://github.com/NurRobin/NurProxy/issues/148

---
Projection from ghosttree. Edits to this file are lost on the next write.
