# apps/engine

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `AGPL-3.0-or-later`.

Python 3.13 / FastAPI / pyHanko / uv. PoC interrupted signing primeiro; persistir estado seguro sem pickle não confiável. Testar digest CMS, ByteRange, alteração incremental, cadeia e revogação. Pytest, Ruff, Pyright. Não aceitar assinatura externa sem verificação. Avaliar Java DSS se gate ICP-Brasil falhar.

Python 3.13 gerenciado por uv sem alterar o Python do sistema: `uv python install 3.13` e, em `apps/engine`, `uv python pin 3.13`. Autenticação de serviço obrigatória em todos os perfis; HTTP apenas em desenvolvimento/testes isolados (SPEC §10 EXC-01), TLS em produção e mTLS opcional.

API canônica (ADR-0014): `packages/protocol/openapi/engine.v1.yaml`; não criar aliases nem rotas fora do contrato.

Estado: P1 E0–E2 (núcleo de assinatura externa). Plano: `docs/plans/P1-engine-cryptographic-core.md`; achados: `docs/architecture/notes/P1-E2-pyhanko-spike.md`.

Comandos (uv 0.13.10 fixado em `[tool.uv] required-version`):

- `uv sync --locked`
- `uv run --locked ruff check . && uv run --locked ruff format --check .`
- `uv run --locked pyright` (strict)
- `SIGNPORT_REQUIRE_OPENSSL=1 uv run --locked pytest -ra` (verificação independente via OpenSSL obrigatória)

Regras específicas:
- Dependências com versão exata; `exclude-newer` é a política de idade mínima. Avançar a data só em revisão.
- O digest assinado é `SHA-256(signed_attrs.dump())`; atributos assinados são gerados uma vez e nunca regenerados na finalização.
- Revogação: nunca usar os modos legados `hard-fail`/`soft-fail` do certvalidator; exigir informação de revogação. Nunca usar raízes padrão (certifi): somente trust bundle explícito.
- PKI, chaves e PDFs de teste são sintéticos e gerados em memória; nenhum `*.pem`, `*.key`, `*.pfx`, `*.der` ou `*.pdf` na árvore (teste de higiene).
