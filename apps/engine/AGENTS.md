# apps/engine

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `AGPL-3.0-or-later`.

Python 3.13 / FastAPI / pyHanko / uv. PoC interrupted signing primeiro; persistir estado seguro sem pickle não confiável. Testar digest CMS, ByteRange, alteração incremental, cadeia e revogação. Pytest, Ruff, Pyright. Não aceitar assinatura externa sem verificação. Avaliar Java DSS se gate ICP-Brasil falhar.

Python 3.13 gerenciado por uv sem alterar o Python do sistema: `uv python install 3.13` e, em `apps/engine`, `uv python pin 3.13`. Autenticação de serviço obrigatória em todos os perfis; HTTP apenas em desenvolvimento/testes isolados (SPEC §10 EXC-01), TLS em produção e mTLS opcional.

API canônica (ADR-0014): `packages/protocol/openapi/engine.v1.yaml`; não criar aliases nem rotas fora do contrato.

Estado: scaffold. Defina comandos de build e teste após bootstrap aprovado.
