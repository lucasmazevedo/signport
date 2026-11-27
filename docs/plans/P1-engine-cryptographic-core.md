# Plano P1 — SignPort Engine Cryptographic Core

Estado: **aprovado** em 27/11/2026 com requisitos complementares (§§11–12). E0–E2 concluídos e mergeados (PR #2, `6539868`); E3–E10 não iniciados. Plano detalhado de E3–E6: `docs/plans/P1-E3-E6-persistence-finalization-validation.md` (aprovado em 27/11/2026; E3–E4 em implementação na `feat/engine-persistence`, E5–E6 na futura `feat/engine-validation`). Base: SPEC v2.3.1, ROADMAP (P0 concluída em `d736a88`, PR #1), ADR-0003, ADR-0013, ADR-0014, contratos `packages/protocol` (279 testes).

## 1. Objetivo e escopo

Provar, com evidência reproduzível, que o Engine consegue: preparar um PDF por atualização incremental com espaço CMS reservado; expor o digest dos atributos CMS assinados; aceitar uma assinatura RSA bruta produzida fora do Engine (equivalente a `SignHash`), verificá-la e incorporá-la sem alterar o ByteRange; retomar o processo após reinício; validar o resultado com dimensões separadas; e produzir PAdES ICP-Brasil AD-RB aceito no VALIDAR com certificado A1 real.

**Dentro da P1:** biblioteca `signport_engine`, estado persistente, validação, política RB, PKI sintética, API HTTP FastAPI das 12 rotas da ADR-0014, CI.
**Fora da P1:** Hub/P1.5, Desktop, A3, carimbo de tempo (RT/ACT), LTV/DSS, aparência visual (ENG-06), lotes, S3, Bird ID, Java DSS (só como fallback avaliado).

Gate de saída do ROADMAP: *synthetic certificate, external CMS digest, signed PDF, independent verification and policy report*, mais a SPEC §13: PDF válido e retomada após restart, com evidência ITI conforme a §28.

## 2. Fatos verificados (fontes oficiais, 27/11/2026)

| Item | Fato | Consequência |
|---|---|---|
| pyHanko | 0.38.2 (19/11/2026), MIT, Python ≥ 3.11, classificador 3.13 | Fixar `==0.38.2`; série 0.x pode quebrar API entre minors |
| pyhanko-certvalidator | 0.33.0, MIT (exigido `<0.34,>=0.33`) | Fixar junto |
| Interrupted signing | `PdfSigner.async_digest_doc_for_signing` → `(PreparedByteRangeDigest, PdfTBSDocument, output)`; `ExternalSigner.signed_attrs(digest, 'sha256', use_pades=True)`; `ExternalSigner(signature_value=…)` + `async_sign_prescribed_attributes`; `PdfTBSDocument.async_finish_signing(output, prep_digest, cms)` | Fluxo exato da SPEC §5; serialização do estado fica conosco |
| `PreparedByteRangeDigest` | `document_digest`, `reserved_region_start`, `reserved_region_end`; documentado como "easily serialised" | Persistível em JSON |
| `PostSignInstructions` | Contém `ValidationContext`/`TimeStamper`; não trivialmente serializável | P1 restringe a RB sem LTV/TS e **exige** que `post_sign_instructions` esteja vazio |
| Política | `CAdESSignedAttrSpec.signature_policy_identifier` existe, mas *"pyHanko does not understand signature policies… taken at face value"* | Regras do AD-RB são responsabilidade do SignPort; validação local não prova conformidade |
| Validação | `async_validate_pdf_signature`, `ades_basic_validation`, `SignatureCoverageLevel`, `PdfSignatureStatus` | Mapear para `ValidationReport` da P0 |
| Dependências | fastapi 0.165.0 (MIT), uvicorn 0.54.0 (BSD), pydantic 2.14.4 (MIT), cryptography 50.0.2 (Apache/BSD), httpx 0.29.0 (BSD), pytest 9.2.0 (MIT), hypothesis 6.170.18 (**MPL-2.0**, só dev), ruff 0.17.6, pyright 1.1.414 | Todas compatíveis com AGPL; MPL apenas em dev |
| uv | 0.13.10 (MIT/Apache) — **não instalado nesta máquina** | E0 instala via instalador oficial ou pacote |
| setup-uv | v10.4.0 (20/11/2026) | Fixar por SHA; respeitar idade mínima |
| Local | Python 3.12.3, OpenSSL 3.0.13 | Python 3.13 via `uv python install 3.13`; OpenSSL serve de verificador independente |

Toda API citada será reconfirmada contra o código da versão fixada no spike E2 antes de virar contrato interno.

## 3. Estrutura proposta (`apps/engine`, AGPL-3.0-or-later)

```text
apps/engine/
  pyproject.toml          # requires-python ==3.13.*, deps fixadas, [tool.uv] exclude-newer
  uv.lock
  .python-version         # 3.13 (uv python pin)
  src/signport_engine/
    api/                  # FastAPI: rotas ADR-0014, auth de serviço, erros HttpError
    core/                 # config (perfis dev/test/prod, EXC-01), erros, ids, clock
    pdf/                  # abertura segura, limites, preparação incremental (pyHanko)
    cms/                  # atributos assinados, verificação RSA bruta, montagem CMS
    certificates/         # inspeção, fingerprint, extração ICP-Brasil (pendente)
    validation/           # pyHanko → ValidationReport; trust bundle; revogação
    policies/icp_brasil/  # AD-RB: OID, hash da LPA, atributos obrigatórios
    storage/              # storage_ref → filesystem privado; artefatos imutáveis
    state/                # estado de preparação versionado, AES-GCM, sem pickle
  tests/{unit,integration,contract,lab}/
  scripts/lab/            # procedimento A1 real (fora do CI)
```

Dependências de runtime: `pyhanko`, `pyhanko-certvalidator`, `cryptography`, `asn1crypto`, `fastapi`, `uvicorn`, `pydantic`. Dev: `pytest`, `pytest-asyncio` (ou anyio), `hypothesis`, `ruff`, `pyright`, `jsonschema` + `referencing` (contratos P0), `httpx` (cliente de teste). Sem `aiohttp` explícito além do transitivo; fetch de revogação desligado por padrão.

## 4. Decisões técnicas centrais

1. **Três digests, um só assinado.** `document_sha256` = SHA-256 do original armazenado (recalculado e comparado com o pedido). `byte_range_digest_b64` = `prep_digest.document_digest` (atributo messageDigest). `signed_attributes_digest_b64` = SHA-256 de `signed_attrs.dump()` (codificação `SET OF`, conforme RFC 5652 §5.4). Um teste prova que esse é exatamente o valor que pyHanko assinaria.
2. **Sem hash duplo.** O teste de referência assina o digest com `cryptography` usando `Prehashed(SHA256)` (semântica de `SignHash`); o caminho `SignData(digest)` deve falhar. O Engine verifica com `public_key.verify(sig, signed_attrs_der, PKCS1v15(), SHA256())` antes de montar o CMS.
3. **Estado persistente sem objetos vivos.** O documento `PreparationState v1` (JSON com schema próprio) contém: ids, versões do schema/pyHanko, referência e SHA-256 do PDF preparado, offsets reservados, os dois digests, `signed_attrs` DER, certificado e cadeia DER, algoritmos, política, expiração e status. É cifrado com AES-256-GCM (`cryptography`; AAD = id + versão) e a chave vem de `ENGINE_STATE_KEY`. Sem pickle, sem `eval`, sem desserialização de objetos.
4. **Os atributos assinados ficam congelados.** São gerados uma única vez na preparação. A finalização reutiliza os bytes persistidos e nunca regenera atributos nem altera o ByteRange.
5. **Idempotência e concorrência.** A finalização é idempotente para o mesmo `(preparation_id, attempt_id, signature)`; divergência retorna `CONFLICT`. Exclusão por lock de arquivo + escrita atômica do artefato (`O_EXCL` + `rename`), de modo que duas finalizações simultâneas produzam um único artefato.
6. **Reserva CMS.** O certificado é conhecido na preparação, então usar a estimativa do pyHanko com margem. Estouro → `CMS_RESERVATION_EXCEEDED`; exige nova preparação e nova autorização.
7. **Validação conservadora.** A confiança vem só do trust bundle versionado. Revogação offline (CRL/OCSP fornecidos) no CI; o fetch online fica desligado por padrão e, quando ligado, passa por um fetcher com allowlist que bloqueia IPs privados e metadata (SSRF), com limites de tempo e tamanho. Falha de rede → `indeterminate`, nunca `passed`.
8. **PDF como entrada hostil.** Limites de bytes e páginas (Capabilities), rejeição de PDF criptografado ou malformado, e parsing com timeout. Isolamento em subprocesso com limites de recursos fica avaliado em E9.

## 5. Etapas incrementais

Cada etapa termina com testes verdes em CI e evidência registrada. Nenhuma etapa marca gate da SPEC sem prova.

### E0 — Bootstrap Python 3.13 com uv
- Instalar uv (instalador oficial, verificando checksum, ou pacote); `uv python install 3.13`; em `apps/engine`, `uv python pin 3.13` e `uv init --package`.
- `pyproject.toml` com versões exatas; `[tool.uv] exclude-newer` como equivalente da política de idade mínima; `uv.lock`.
- Ruff (lint + format), Pyright strict em `src`, pytest com `-W error`.
- Atualizar ROADMAP (P0 concluída com evidência: PR #1, `d736a88`, 4 checks) e `apps/engine/AGENTS.md` com os comandos.
- **Aceite:** `uv sync --locked`, `uv run ruff check`, `uv run pyright` e `uv run pytest` passam localmente com Python 3.13.x; o relatório de licenças das dependências (resolvidas pelo lockfile) não contém GPL/AGPL incompatível nem licença desconhecida; o sistema continua em 3.12.

### E1 — PKI e documentos sintéticos
- Gerador de PKI de laboratório com `cryptography.x509`: raiz → intermediária → folha RSA-2048 (KU digitalSignature + nonRepudiation; SAN com OIDs no formato ICP-Brasil e **valores fictícios**). Também folhas revogada, expirada, com KU errada e RSA-1024; CRL e OCSP offline.
- Chaves geradas em tempo de teste (`tmp_path`), nunca gravadas no repositório.
- PDFs sintéticos gerados por código: simples, com assinatura prévia, com DocMDP, criptografado, malformado e grande.
- **Aceite:** fixtures reprodutíveis; teste garante que nenhum `*.pem`, `*.key`, `*.pfx` ou PDF não sintético entra no repositório; os certificados são parseáveis por `cryptography` e por `openssl x509`.

### E2 — Spike de assinatura interrompida (gate go/no-go do pyHanko)
- Num único processo: preparar com `ExternalSigner` (placeholder de 256 bytes) → `signed_attrs` → assinar o digest com `Prehashed` → `async_sign_prescribed_attributes` → `async_finish_signing`.
- Registrar em `docs/architecture/` (nota técnica) o comportamento real da versão fixada: conteúdo de `signed_attrs`, ausência de `signingTime` com `use_pades=True`, forma de `post_sign_instructions` sem LTV/TS, tamanho da reserva.
- **Aceite:**
  - (a) A validação do pyHanko dá intacta e válida contra a raiz sintética.
  - (b) A verificação independente passa: OpenSSL `cms -verify` sobre `/Contents` com o conteúdo do ByteRange como dados destacados.
  - (c) Uma assinatura `SignData(digest)` é rejeitada.
  - (d) Os três digests são distintos.
  - (e) Vetor conhecido: o `signed_attributes_digest_b64` coincide com o valor que pyHanko assina internamente quando usado com `SimpleSigner` e a mesma chave.
  - Se (a), (b) ou (e) falhar sem correção pela API pública → abrir proposta de ADR sobre Java DSS antes de continuar.

### E3 — Preparação persistente
- Implementar `PreparationState v1` cifrado, storage de filesystem por `storage_ref` validado (padrão da P0, sem path traversal), PDF preparado imutável com hash, expiração e cancelamento com limpeza.
- **Aceite:**
  - Preparar no processo A e finalizar no processo B (subprocess novo) gera PDF válido — **gate ENG-03**.
  - Estado adulterado (bit flip, chave errada, versão desconhecida) → falha fechada.
  - PDF preparado alterado (hash divergente) → rejeitado.
  - Estado expirado → `PREPARATION_EXPIRED`.
  - Teste estático: nenhum `pickle`, `marshal`, `shelve` ou `eval` em `src`.

### E4 — Finalização com verificação
- Checar algoritmo, fingerprint do certificado e comprimento da assinatura igual ao módulo; verificar RSA sobre os atributos persistidos; montar o CMS; checar a reserva; gravar o artefato atômico; garantir a idempotência.
- **Aceite:**
  - Testes negativos: assinatura de outro digest, de outra chave, truncada, com padding PSS, `SignData(digest)`, certificado divergente, algoritmo divergente → `SIGNATURE_INVALID`, `CERTIFICATE_MISMATCH` ou `UNSUPPORTED_ALGORITHM`.
  - Repetição idêntica → mesma resposta.
  - Repetição divergente → `CONFLICT`.
  - Duas finalizações concorrentes → um único artefato.
  - Estouro de reserva simulado → `CMS_RESERVATION_EXCEEDED`.

### E5 — Validação criptográfica e relatório
- **Risco crítico herdado da E2:** o modo legado `hard-fail` do pyhanko-certvalidator 0.33.0 ignora CRLs fornecidas quando o certificado não declara ponto de distribuição, aceitando signatário revogado. Requisitos obrigatórios da E5 (revisão de 27/11/2026): exigir evidência válida de revogação; ausência de informação nunca equivale a certificado válido; nenhum fallback silencioso para soft-fail; distinguir certificado revogado, evidência indisponível e evidência inválida; considerar o instante relevante da validação; usar exclusivamente trust stores configurados explicitamente, sem fallback implícito para as raízes Mozilla do `certifi`; separar trust stores sintéticos e ICP-Brasil; bloquear a liberação automática de documentos indeterminados. Preservar o teste de regressão `test_legacy_hard_fail_mode_skips_crls_without_distribution_points`.
- Mapear o resultado do pyHanko para `ValidationReport` (integrity, coverage, chain, validity_period, revocation, key_usage, policy, timestamp, modifications) e para a decisão final; trust bundle versionado; `POST /v1/certificates/inspect|validate`.
- **Aceite:**
  - Certificado válido → `valid`.
  - Revogado, expirado, KU errada ou cadeia não confiável → `invalid` na dimensão correta.
  - CRL/OCSP indisponível → `indeterminate`.
  - PDF modificado após a assinatura (incremental malicioso e bytes alterados) → integridade, cobertura ou modificações falham.
  - Raiz enviada pelo cliente é ignorada.
  - O fetcher bloqueia `127.0.0.1`, `169.254.169.254`, RFC 1918, redirecionamento para IP privado e esquemas não-http.

### E6 — Assinaturas incrementais e DocMDP
- Segunda assinatura sobre PDF já assinado; certificação com DocMDP; PDF com permissão que proíbe nova assinatura.
- **Aceite:**
  - Ambas as assinaturas validam e a primeira continua com cobertura de revisão correta.
  - DocMDP proibitivo → rejeitado antes de preparar.
  - Nenhuma normalização do PDF após a assinatura.

### E7 — Política ICP-Brasil PAdES AD-RB
- Levantar no ITI, com fonte e data registradas: a versão vigente do DOC-ICP-15.03 e as alterações (inclusive IN 34/2025 citada na SPEC), o OID da política PAdES AD-RB, a LPA (artefato e hash) e os atributos obrigatórios e proibidos.
- Implementar `signature_policy_identifier` com o hash da política, `signing-certificate-v2`, a ausência de `signingTime` (uso de `/M`) e o subfilter `ETSI.CAdES.detached`.
- Implementar uma verificação local de política, sem afirmar conformidade: `policy` e `validation_status=experimental`.
- **Aceite:**
  - OIDs e hash conferidos contra o artefato oficial baixado (hash registrado).
  - Testes de presença e ausência de atributos.
  - `GET /v1/policies` só promove para `iti_validated_samples` após E8.
  - Se o ITI exigir algo que o pyHanko não produz pela API pública → proposta de ADR (Java DSS).
- Trust bundle e LPA reais **não** entram no Git até a decisão L08 (direitos de redistribuição); são baixados por script com hash fixado.

### E8 — Laboratório com A1 real e evidência VALIDAR
Procedimento em §7. **Aceite:** um PDF sintético assinado pelo fluxo interrompido (preparar → assinar digest fora do Engine com a chave A1 → finalizar em outro processo) é aceito no VALIDAR no perfil AD-RB. A evidência fica registrada (data, versões, hash do PDF, captura ou relatório do VALIDAR, sem dados pessoais no Git), e a validação local concorda com o resultado.

### E9 — API HTTP (ADR-0014)
- FastAPI com as 12 rotas, autenticação de serviço (`ENGINE_SERVICE_TOKEN`; mTLS opcional em produção), perfis EXC-01 (HTTP só em dev/test; produção exige TLS), `Idempotency-Key`, `X-Correlation-Id`, erros `HttpError` sem stack trace, limites de corpo, health/ready, logs sem PDF/CPF/assinatura.
- **Aceite:**
  - Testes de contrato validam requisições e respostas contra os JSON Schemas da P0 (lidos de `packages/protocol`, `jsonschema` 2020-12, sem rede).
  - Teste garante que o conjunto de rotas é exatamente o da ADR-0014.
  - Os casos negativos das fixtures P0 do Engine são rejeitados com 422.
  - Sem token → 401.
  - Produção com URL http ou sem token → recusa iniciar.

### E10 — Robustez e fechamento
- Hypothesis/fuzz no parser de entrada e no estado; PDFs patológicos com timeout; medição P95 de preparação e finalização para PDF de 2 MB (registrada, não prometida); documentação; atualizar ROADMAP e CHANGELOG com a evidência.
- **Aceite:** checklist da §8 completo.

## 6. Testes automatizados (resumo)

| Categoria | Exemplos |
|---|---|
| Unitários | Cálculo dos três digests, serialização e criptografia do estado, validação de `storage_ref`, mapeamento de erros |
| Integração | Fluxo completo em processo e entre processos; incremental; DocMDP; validação com PKI sintética |
| Negativos | Hash duplo, assinatura ou certificado trocado, PSS, truncada, estado adulterado ou expirado, PDF alterado, criptografado ou malformado, raiz do cliente, SSRF, reserva excedida, concorrência |
| Contrato | Requisições e respostas versus schemas P0; rotas da ADR-0014; taxonomia de erros |
| Independentes | OpenSSL `cms -verify`; leitura por segundo parser (`pdfsig`/poppler se disponível no runner) |
| Laboratório (fora do CI) | A1 real + VALIDAR |

## 7. Procedimento seguro com certificado A1 real

1. O PFX fica **fora do repositório** (ex.: `~/.signport-lab/`, permissão `0600`). Não é copiado para `/tmp`, para o repositório, para fixtures nem para o CI.
2. Um script de laboratório (`scripts/lab/sign_with_a1.py`, que nunca roda no CI) recebe o caminho do PFX por argumento e lê a senha com `getpass`: nunca por argumento, variável de ambiente ou arquivo. Ele carrega o PFX com `cryptography.pkcs12` e assina **apenas** o `signed_attributes_digest_b64` com `Prehashed` (simulando o Desktop). Não exporta, não registra nem persiste a chave; descarta referências ao final.
3. O Engine roda localmente no perfil `test`, com o estado em diretório temporário.
4. O documento assinado é um **PDF sintético**, sem dados clínicos. O PDF assinado conterá o certificado do titular, inclusive nome e CPF. Ele fica em diretório ignorado pelo Git e **não é commitado**.
5. O envio ao VALIDAR é feito manualmente por você, ciente de que o PDF expõe os dados do seu certificado ao ITI.
6. Logs mostram só fingerprints e hashes; um teste garante que a senha e o DER da chave não aparecem na saída.
7. A evidência registrada no Git inclui data, versões, hash do PDF, perfil e resultado do VALIDAR. Não inclui CPF, nome nem o PDF.
8. Um A1 não satisfaz o gate do A3 (P2).

## 8. Critérios de aceite da P1

- [ ] E0–E10 com testes verdes no GitHub Actions (job `engine`: setup-uv fixado por SHA, `uv sync --locked`, ruff, pyright, pytest; permissões mínimas; sem segredos).
- [ ] Preparação e finalização em processos distintos (ENG-03).
- [ ] Assinatura externa verificada antes da montagem; hash duplo rejeitado (ENG-04).
- [ ] Os três digests distintos e expostos conforme o OpenAPI da P0 (ENG-01/02).
- [ ] Validação com dimensões separadas; revogação indisponível → `indeterminate` (ENG-05).
- [ ] Assinatura incremental preservando a anterior; modificação pós-assinatura detectada.
- [ ] Verificação independente (OpenSSL) no CI.
- [ ] AD-RB: OID e hash da política conferidos contra a fonte oficial; PDF com A1 real aceito no VALIDAR (evidência registrada).
- [ ] API HTTP aderente aos schemas P0 e às rotas da ADR-0014; autenticação de serviço; EXC-01.
- [ ] Sem chaves, PFX, PDFs reais ou dados pessoais no Git; licenças das dependências verificadas.
- [ ] Gates ainda pendentes registrados explicitamente: RT/ACT, LTV, A3, múltiplas ACs ICP-Brasil reais e trust bundle redistribuível (L08).

## 9. Riscos e limitações

| Risco | Impacto | Mitigação |
|---|---|---|
| pyHanko não interpreta políticas | AD-RB pode ficar formalmente incompleto sem que a validação local acuse | Verificador de política próprio; VALIDAR como árbitro; status `experimental` |
| Exigência do ITI não produzível pela API pública | Bloqueia RB | Gate em E2/E7; proposta de ADR para Java DSS (fallback da ADR-0003) |
| pyHanko 0.x muda API entre minors | Quebra no upgrade | Versão exata, testes de contrato internos, upgrade só com PR dedicado |
| `PostSignInstructions` não serializável | Impede LT/LTA interrompidos | P1 sem LTV/TS; LT/LTA viram uma revisão posterior própria (fora da P1) |
| Estimativa de reserva | CMS não cabe | Margem; `CMS_RESERVATION_EXCEEDED` → nova preparação |
| Cadeias ICP-Brasil reais (extensões, LCR só HTTP) | Validação indeterminada | Fetcher com allowlist; resultados indeterminados não publicam |
| Direitos de redistribuição das raízes ICP-Brasil e da LPA | Não podem ir para o Git/imagem | Download com hash fixado (L08 pendente) |
| PDFs maliciosos | DoS ou exploração | Limites, timeout, rejeição de PDF criptografado, isolamento avaliado em E9/E10 |
| Mantenedor único do pyHanko | Risco de continuidade | Monitorar releases; manter o fallback documentado |
| Modos legados de revogação do certvalidator (`hard-fail`/`soft-fail`) aceitam signatário revogado sem CRL DP | **Crítico**: validação falsamente positiva | Requisitos da E5 (§5); teste de regressão preservado |
| Raízes Mozilla do `certifi` (MPL-2.0, transitivo) como confiança implícita | Confiança indevida | Trust stores explícitos e separados; nunca padrões |
| Margem de reserva CMS (≈33% observada) | Evidência experimental, não garantia | Estouro → `CMS_RESERVATION_EXCEEDED`, nova preparação e nova autorização; ByteRange nunca alterado após a assinatura |
| Hypothesis MPL-2.0 | Copyleft fraco | Somente dev, não distribuído |
| Dados pessoais no laboratório A1 | Vazamento | Procedimento da §7 |

## 10. Decisões da revisão de 27/11/2026

1. Etapas E0–E10 aprovadas.
2. uv instalado da distribuição oficial da Astral, versão fixada (0.13.10) e checksum verificado.
3. Python 3.13 gerenciado pelo uv, sem alterar o Python do sistema.
4. AES-256-GCM aprovado para o estado das preparações (requisitos em §11.1).
5. Download dos artefatos ICP-Brasil por script aprovado, sem redistribuição até resolver L08.
6. Procedimento técnico A1 aprovado; **autorização explícita obrigatória antes da E8**.
7. pyHanko permanece o motor principal; Java DSS é contingência. Limitações do pyHanko só justificam proposta de migração com evidência reproduzível.

## 11. Requisitos complementares

### 11.1 Persistência criptográfica (E3)
- `AESGCM` da biblioteca `cryptography`; chave aleatória de 256 bits; nonce de 96 bits único por operação sob a mesma chave; tag de 128 bits.
- Envelope versionado com `key_id`; AAD vinculada ao contexto imutável da preparação (id, versão do schema, document_sha256, certificate_sha256, prepared_pdf_sha256).
- Configuração: `ENGINE_STATE_KEY` e `ENGINE_STATE_KEY_ID`; `ENGINE_STATE_KEY_FILE` previsto para produção. Estrutura pronta para rotação (decifrar com chaves antigas por `key_id`, cifrar com a ativa).
- Nunca gerar chave silenciosamente na inicialização: sem chave configurada, o Engine não inicia.
- Sem pickle. Testes: adulteração, troca de contexto (AAD), chave incorreta, `key_id` desconhecido e recuperação.
- Atomicidade (escrita temporária + `rename`), idempotência e recuperação após falhas; compatibilidade com os contratos públicos da P0.

### 11.2 ICP-Brasil (E7)
- Versionar apenas scripts, manifestos, hashes e metadados permitidos.
- Validar autenticidade, vigência, OID e hash dos artefatos oficiais; trust stores sintéticos e reais separados.
- Não presumir que o pyHanko interpreta políticas ICP-Brasil.
- Aprovação de um PDF no VALIDAR não é declaração de conformidade formal nem homologação.

### 11.3 Certificado A1 (E8)
- A chave privada fica exclusivamente no processo externo de teste, que simula o futuro provedor de assinatura; o Engine recebe somente certificado público, cadeia e assinatura RAW.
- Nunca no Git: PFX, senha, chave privada, PDF assinado real ou relatórios com dados pessoais.
- Envio ao VALIDAR manual, pelo titular, após autorização específica.

### 11.4 Estratégia Git
PRs sequenciais, cada branch criada da `main` atualizada após o merge da anterior:

| Branch | Etapas |
|---|---|
| `feat/engine-poc` | E0–E2 |
| `feat/engine-persistence` | E3–E4 |
| `feat/engine-validation` | E5–E6 |
| `feat/engine-icp-brasil` | E7–E8 |
| `feat/engine-api` | E9–E10 |

Commit, push e PR somente com autorização; sem co-autoria nos commits.

### 11.5 Critérios de aceite do primeiro marco (E0–E2)
- [x] Ambiente reproduzível com `uv.lock` (verificado também em cópia limpa).
- [x] Dependências e licenças verificadas.
- [x] Ruff, Pyright (strict) e Pytest aprovados localmente.
- [x] PKI e PDFs sintéticos.
- [x] Preparação externa de PDF.
- [x] Preservação dos atributos CMS exatos.
- [x] RSA SHA-256 PKCS#1 v1.5 sem hash duplo.
- [x] Finalização de PDF.
- [x] Verificação independente pelo OpenSSL.
- [x] Validação documental pelo pyHanko.
- [x] Casos negativos: adulteração, digest incorreto, certificado divergente, assinatura inválida.
- [x] Compatibilidade com os contratos relevantes da P0.
- [ ] Job `engine` no GitHub Actions executado com sucesso (definido com permissões mínimas e Actions fixadas por SHA; só pode ser comprovado após push autorizado).

Evidências e achados: `docs/architecture/notes/P1-E2-pyhanko-spike.md`.

## 12. Requisitos da revisão do PR #2 (27/11/2026)

### 12.1 Critérios obrigatórios de E3/E4
A finalização deve, a partir do estado persistido e antes de gravar o artefato:
- [ ] Recalcular o fingerprint SHA-256 do certificado recuperado do estado e compará-lo com o vinculado à preparação e ao pedido.
- [ ] Validar a correspondência entre o certificado e o atributo `signingCertificateV2` (hash do certificado e `issuerSerial`).
- [ ] Validar os algoritmos vinculados à preparação (digest e assinatura) contra o pedido e contra a política configurada.
- [ ] Validar os offsets da região reservada (início < fim, dentro do arquivo, capacidade par e positiva, delimitadores `<` e `>`).
- [ ] Conferir que os offsets persistidos correspondem ao `/ByteRange` efetivamente gravado no PDF preparado.
- [ ] Recalcular o digest dos bytes cobertos pelo ByteRange a partir do PDF preparado persistido.
- [ ] Validar que o `messageDigest` dos atributos CMS corresponde ao digest recalculado (E2 já compara com o valor persistido; E4 compara com o recalculado).
- [ ] Garantir que nenhum byte coberto pelo ByteRange é modificado na finalização (comparação byte a byte fora da região reservada).
- [ ] Calcular o SHA-256 do artefato final e persisti-lo junto da referência imutável.
- [ ] Garantir atomicidade, idempotência, concorrência e recuperação após falhas.
- [ ] Não publicar automaticamente artefatos inválidos ou indeterminados: o Engine só marca `completed`; a liberação depende do relatório de validação (E5) e da decisão do Hub.

### 12.2 Avaliação: versão patch do Python no CI
Situação atual: `.python-version` = `3.13` e uv fixado em 0.13.10. O uv resolve `3.13` contra o manifesto de downloads embutido na própria versão, então na prática obtém sempre 3.13.18 enquanto o uv não mudar. Há porém dois pontos frágeis: (a) um interpretador 3.13 do sistema no runner pode ser escolhido no lugar do gerenciado; (b) o patch muda implicitamente quando o uv é atualizado.

Decisão (aprovada em 27/11/2026, implementada em `feat/engine-persistence`):
1. Fixar `.python-version` em `3.13.18` (patch exato), mantendo `requires-python = "==3.13.*"` para que atualizações de segurança do patch sejam apenas uma alteração revisada de uma linha.
2. No CI, `UV_PYTHON_PREFERENCE=only-managed` e `uv python install` sem argumento (lê `.python-version`), impedindo o uso do Python do runner.
3. Teste de ambiente que compara `sys.version_info[:3]` com `.python-version`.
4. Atualizar patch e uv juntos em PR dedicado (ou via Renovate/Dependabot quando configurados), com os mesmos checks; avisos de segurança do CPython têm prioridade sobre a data de corte `exclude-newer`.
