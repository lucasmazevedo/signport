# apps/engine

Leia ../../AGENTS.md quando estiver dois níveis abaixo da raiz; em qualquer caso siga o AGENTS.md raiz e SPEC.md.

Licença planejada: `AGPL-3.0-or-later`.

Python 3.13 / FastAPI / pyHanko / uv. PoC interrupted signing primeiro; persistir estado seguro sem pickle não confiável. Testar digest CMS, ByteRange, alteração incremental, cadeia e revogação. Pytest, Ruff, Pyright. Não aceitar assinatura externa sem verificação. Avaliar Java DSS se gate ICP-Brasil falhar.

Python 3.13.18 (patch exato em `.python-version`) gerenciado por uv sem alterar o Python do sistema: `uv python install` em `apps/engine`; no CI, `UV_PYTHON_PREFERENCE=only-managed`. Autenticação de serviço obrigatória em todos os perfis; HTTP apenas em desenvolvimento/testes isolados (SPEC §10 EXC-01), TLS em produção e mTLS opcional.

API canônica (ADR-0014): `packages/protocol/openapi/engine.v1.yaml`; não criar aliases nem rotas fora do contrato.

Estado: P1 E0–E2 concluídas; E3–E4 (persistência e finalização) em revisão na `feat/engine-persistence`. Planos: `docs/plans/P1-engine-cryptographic-core.md` e `docs/plans/P1-E3-E6-persistence-finalization-validation.md`; achados: `docs/architecture/notes/P1-E2-pyhanko-spike.md`.

Configuração (falha segura: sem configuração válida o Engine não inicia):
- `ENGINE_DATA_DIR` (absoluto, local, 0700; nunca NFS/SMB) e `ENGINE_INSTANCE_ID` (UUID gravado no banco na primeira inicialização).
- Chave: `ENGINE_STATE_KEY` + `ENGINE_STATE_KEY_ID`, ou `ENGINE_STATE_KEY_FILE` (keyring JSON 0600, fora de `ENGINE_DATA_DIR`). Nunca gerar chave na inicialização.
- Opcionais: `ENGINE_SQLITE_BUSY_TIMEOUT_MS` (5000), `ENGINE_COMPLETION_LEASE_SECONDS` (60), `ENGINE_COMPLETION_WAIT_MS` (30000), `ENGINE_COMPLETION_GRACE_SECONDS` (300), `ENGINE_LOCK_TIMEOUT_MS` (30000), `SIGNING_PREPARATION_TTL` (600), `ENGINE_TERMINAL_RETENTION_SECONDS` e `ENGINE_ARTIFACT_RETENTION_SECONDS` (7 dias, contados de `terminal_at`), `ENGINE_ORPHAN_GRACE_SECONDS` (3600, apenas defesa adicional), `ENGINE_MAX_PDF_BYTES` (20 MiB).
- Rotação (janela de manutenção exclusiva): nova chave ativa no keyring, antigas mantidas para leitura; `rewrap()` e depois `retire_key(antiga)` (recusa enquanto houver uso no banco ou em arquivos; histórico preservado; chave aposentada nunca volta a ser ativa). O registro de chaves recusa id religado a outro material e material reutilizado sob outro id. Após restaurar backup: rotacionar para chave nunca usada e chamar `recover_after_restore()` antes de qualquer cifragem. Processos em execução com keyring anterior são recusados (`SERVICE_UNAVAILABLE`) assim que outro processo registra uma chave nova ou aposenta a ativa: reinicie todos os processos com o novo keyring. A inicialização sincroniza o registro sob o lock compartilhado.

Comandos (uv 0.13.10 fixado em `[tool.uv] required-version`):

- `uv sync --locked`
- `uv run --locked ruff check . && uv run --locked ruff format --check .`
- `uv run --locked pyright` (strict)
- `SIGNPORT_REQUIRE_OPENSSL=1 uv run --locked pytest -ra` (verificação independente via OpenSSL obrigatória)

Regras específicas:
- Dependências com versão exata; `exclude-newer` é a política de idade mínima. Avançar a data só em revisão.
- O digest assinado é `SHA-256(signed_attrs.dump())`; atributos assinados são gerados uma vez e nunca regenerados na finalização.
- Revogação: nunca usar os modos legados `hard-fail`/`soft-fail` do certvalidator; exigir informação de revogação. Nunca usar raízes padrão (certifi): somente trust bundle explícito.
- Persistência: somente via `PreparationRepository`; transições por compare-and-set; verificar antes de transicionar (assinatura inválida não consome a preparação); artefato imutável publicado antes do commit `completed`; `completed` nunca significa validade normativa.
- Tudo o que for sensível e persistido pelo Engine (estado, PDF preparado, PDF final) é cifrado com AES-256-GCM (`cryptography`), subchaves HKDF por finalidade e AAD com instalação, preparação e finalidade; nenhum PDF em claro no disco.
- `row_mac` e cadeia de eventos detectam adulteração e rollback parcial *inconsistente*; não detectam restauração coordenada (preparação junto com a cadeia anterior, contadores autenticados antigos) nem do armazenamento inteiro (riscos residuais documentados).
- Finalização protegida por `FencingToken` (dono + `state_version` + lease vigente); recuperação só adota artefato após a mesma verificação semântica do CMS e do vínculo. Remoção física de arquivos só sob lock de escrita, após checar referências e intents.
- PKI, chaves e PDFs de teste são sintéticos e gerados em memória; nenhum `*.pem`, `*.key`, `*.pfx`, `*.der` ou `*.pdf` na árvore (teste de higiene).
