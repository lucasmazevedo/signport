# packages/protocol

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `Apache-2.0`.

OpenAPI 3.1 / JSON Schema 2020-12. Fonte canônica de DTOs, erros e mensagens Native Messaging. Versionar incompatibilidades; fixtures sintéticas e testes cross-language. Não inventar contrato Bird ID.

Estado: P0 em revisão. Comandos (Node.js >= 22.12, pnpm):

- `pnpm install --frozen-lockfile`
- `pnpm run check` — Redocly lint e testes de contrato Vitest
- `pnpm run fixtures:crypto` — regenera vetores sintéticos (chaves efêmeras, nunca gravadas)

Regras: schemas fechados (`additionalProperties: false`); todo caso negativo tem `reason`; nenhum dado real; não renomear campos de digest; mudanças incompatíveis exigem nova versão (ver README).
