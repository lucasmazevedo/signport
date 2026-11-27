# apps/extension

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `GPL-3.0-or-later`.

TypeScript / WXT / Manifest V3 / React opcional. Permissões mínimas, instâncias confiáveis, ponte por origem autorizada, permissões opcionais e revogação. Não confiar em payload da página. Não expor signHash genérico. Vitest / Playwright. Testar Chrome e Edge e políticas das lojas.

Mensagens conforme `packages/protocol/schemas/v1/native/` (protocolo 1). Negociar com `getVersion` antes de outros comandos e reportar `VERSION_UNSUPPORTED` com as listas de versões; nunca falhar silenciosamente (SPEC §8.4).

Estado: scaffold. Defina comandos de build e teste após bootstrap aprovado.
