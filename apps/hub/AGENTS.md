# apps/hub

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `AGPL-3.0-or-later`.

Laravel 13 / PHP 8.4 / React 19 / Inertia 2. Monólito modular, tenancy, policies, filas, auditoria e storage privado. Não manipular PIN ou construir CMS. Testar isolamento, idempotência, webhooks e recuperação. Pest, Larastan, Pint. Engine exclusivamente em rede privada.

Fase P1.5 (ADR-0013) é o primeiro bootstrap deste componente: somente identidade da instalação, JWS ES256/JWKS, persistência, consumo atômico de uso único, expiração, revogação, vinculação completa e auditoria mínima, com testes de concorrência e replay. JWS ES256 com assinatura R||S de 64 bytes (converter DER do `openssl_sign`); JCS RFC 8785 validado contra `fixtures/v1/crypto/jcs.vectors.json`; rejeitar JSON com membros duplicados (o `json_decode` do PHP aceita silenciosamente o último). Recusar `ENGINE_BASE_URL` `http://` em produção (SPEC §10 EXC-01). Contratos em `packages/protocol/openapi/hub-authorization.v1.yaml`; não criar microsserviço. P5 expande este Hub.

Estado: scaffold. Defina comandos de build e teste após bootstrap aprovado.
