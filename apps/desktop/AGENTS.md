# apps/desktop

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `GPL-3.0-or-later`.

.NET 10 LTS / C# / Windows CNG/CAPI / PKCS11Interop fallback / WPF consentimento. Native Messaging stdio, limites de mensagem, logs stderr. Validar JWS e consumir nonce atomicamente antes de assinar; sem listener localhost. xUnit, SoftHSM e hardware real; não armazenar PIN.

Mensagens conforme `packages/protocol/schemas/v1/native/`; autorização conforme `schemas/v1/authorization/` e consumo em `POST /api/v1/local/authorizations/consume` (P1.5). Ordem obrigatória em `claims.schema.json`: rejeitar membros JSON duplicados, ES256/R||S apenas, chave do armazenamento local vinculada à instalação, hash JCS do manifesto antes de exibir consentimento, exibir exatamente o manifesto assinado, consumo online confirmado antes da chave (`AUTHORIZATION_CONSUME_FAILED` aborta sem assinar), `SignHash()` e nunca `SignData()`. Vetores em `fixtures/v1/crypto/`. Negociação via `getVersion` (SPEC §8.4). Instalador: WiX Toolset/MSI, sujeito à validação dos termos da versão.

Estado: scaffold. Defina comandos de build e teste após bootstrap aprovado.
