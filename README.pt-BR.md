# SignPort

**Uma interface. Diferentes certificados.**

Infraestrutura aberta e self-hosted para assinaturas digitais, voltada a desenvolvedores.

[English](README.md) · [Especificação](SPEC.md) · [Roadmap](ROADMAP.md) · [Contribuição](CONTRIBUTING.md) · [Segurança](SECURITY.md)

> **Pré-alpha:** estrutura inicial e documentação. Ainda não existe serviço de assinatura funcional, SDK publicado ou conformidade ICP-Brasil comprovada.

## O que é e o que resolve?

O SignPort pretende reduzir a dependência de motores proprietários, tarifas por documento e integrações fragmentadas de certificados digitais. A proposta é disponibilizar uma API unificada, com adaptadores para certificados locais e em nuvem, mantendo documentos sob controle do operador. O nome remete a uma porta de entrada e à arquitetura Ports & Adapters.

## Recursos planejados

- A1 instalado, A3 USB e smart cards; Windows inicialmente.
- Bird ID opcional, sujeito às condições do fornecedor.
- Assinaturas PAdES, políticas ICP-Brasil, validação e assinatura externa.
- Assinaturas individuais, em lote e múltiplos signatários.
- API REST, SDKs, auditoria, multi-tenancy e instalação própria.

| Componente | Tecnologia | Licença definida como estratégia |
|---|---|---|
| [Hub](apps/hub/) | Laravel, React, Inertia | AGPL-3.0-or-later |
| [Engine](apps/engine/) | Python, FastAPI, pyHanko | AGPL-3.0-or-later |
| [Desktop](apps/desktop/) | C#, .NET, CNG, PKCS#11 | GPL-3.0-or-later |
| [Extension](apps/extension/) | TypeScript, WXT, MV3 | GPL-3.0-or-later |
| [SDKs](packages/) e protocolo | PHP, TypeScript, OpenAPI, JSON Schema | Apache-2.0 |
| [Bird ID](providers/birdid/) | PHP, OAuth2, REST | AGPL-3.0-or-later |
| [Documentação](docs/) | Markdown, VitePress (planejado) | CC-BY-4.0 |

## Como começar

Leia [SPEC.md](SPEC.md) v2.3, [AGENTS.md](AGENTS.md) e [ROADMAP.md](ROADMAP.md). A primeira etapa é P0, descrita em [docs/first-agent-task.md](docs/first-agent-task.md). Ainda não há instalação executável ou Compose funcional.

## Segurança e governança

Chaves privadas e PIN não devem ser enviados ao backend; autorizações devem ser vinculadas ao documento e certificado. Sem telemetria obrigatória ou servidor central do mantenedor. Serviços externos e infraestrutura podem ter custos próprios.

Fundador e mantenedor inicial: Lucas Azevedo. Repositório pessoal inicialmente, com possibilidade de organização futura. Consulte [GOVERNANCE.md](GOVERNANCE.md) e [LICENSE](LICENSE). A concessão formal das licenças e a titularidade precisam ser confirmadas antes da publicação pública. O projeto não afirma homologação pelo ITI.
