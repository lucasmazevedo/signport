# apps/engine — SignPort Engine

Licença planejada: `AGPL-3.0-or-later`. Serviço privado (SPEC §7, ADR-0014). Consulte AGENTS.md e SPEC.md na raiz.

**Estado: P1 E0–E2.** Núcleo de assinatura PAdES interrompida com assinante RSA externo (`signport_engine.pdf.external_signing`): preparação incremental, digest ByteRange, atributos CMS congelados, verificação da assinatura bruta antes da montagem do CMS e finalização. Ainda **não** há estado persistente (E3), relatório de validação (E5), política ICP-Brasil (E7) nem API HTTP (E9). Não usar em produção.

```bash
uv sync --locked
SIGNPORT_REQUIRE_OPENSSL=1 uv run --locked pytest -ra
```
