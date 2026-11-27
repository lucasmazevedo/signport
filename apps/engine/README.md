# apps/engine — SignPort Engine

Licença planejada: `AGPL-3.0-or-later`. Serviço privado (SPEC §7, ADR-0014). Consulte AGENTS.md e SPEC.md na raiz.

**Estado: P1 E0–E4 (E3–E4 em revisão).** Núcleo de assinatura PAdES interrompida com assinante RSA externo, agora persistente: `PreparationService` (`signport_engine.service`) prepara, guarda o estado cifrado (SQLite em WAL + filesystem privado, AES-256-GCM), finaliza com verificação completa dos vínculos criptográficos, é idempotente, seguro entre processos e recuperável após falhas. Ainda **não** há relatório de validação nem política de revogação (E5), assinaturas incrementais (E6), política ICP-Brasil (E7) nem API HTTP (E9). Não usar em produção; nenhuma conformidade normativa é declarada.

```bash
uv sync --locked
SIGNPORT_REQUIRE_OPENSSL=1 uv run --locked pytest -ra
```
