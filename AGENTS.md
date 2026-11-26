# AGENTS.md — regras obrigatórias para agentes e colaboradores

## Fonte de verdade
Leia SPEC.md (v2.3), ROADMAP.md e o AGENTS.md mais próximo da área alterada. Se houver conflito, regras de segurança prevalecem; consulte os ADRs da seção 26 e as seções 22–24 e 27–29. Não altere decisões aprovadas sem registrar proposta de ADR e obter aprovação humana. Use SignPort como marca e signport como identificador técnico; ADR-0012 na seção 29. Este arquivo é operacional; não substitui a especificação.

## Fluxo de trabalho
1. Identifique requisito, componente, dependências e critérios de aceite; proponha mudanças pequenas e verificáveis.
2. Inspecione o código e testes existentes antes de editar. Não invente APIs de bibliotecas: confirme documentação da versão fixada.
3. Implemente somente o escopo solicitado; não introduza frameworks, serviços, dependências ou upgrades sem justificar.
4. Inclua testes positivos, negativos e de contrato; execute comandos disponíveis e informe resultados reais, inclusive falhas e testes não executados.
5. Atualize contratos, documentação e roadmap quando necessário. Não marque gates como concluídos sem evidência.
6. Não faça commit, push, publicação, alteração de licença, exclusão destrutiva ou acesso a produção sem autorização explícita. Preserve alterações do usuário.

## Arquitetura e licenças
Hub Laravel/React é fonte de verdade do workflow; Engine FastAPI/pyHanko é privado; Desktop .NET acessa chaves locais; Extension WXT/MV3 usa Native Messaging; SDKs independentes. Protocol OpenAPI 3.1/JSON Schema é canônico. PostgreSQL 18, Valkey, filesystem privado e S3 opcional. Não introduzir listener localhost nem servidor central obrigatório. Hub/Engine e Bird ID adapter AGPL-3.0-or-later; Desktop/Extension GPL-3.0-or-later; SDKs/Protocol Apache-2.0; docs CC-BY-4.0. Infra e scripts do núcleo: AGPL proposta. Não copiar código copyleft para SDKs permissivos. Verificar licenças transitivas e direitos de distribuição; adicionar SPDX e avisos conforme aplicável. Titularidade e concessão formal permanecem pendentes.

## Segurança inegociável
- Nunca exportar chave privada, armazenar PIN ou enviar PIN ao backend. Não usar certificados, PDFs clínicos ou credenciais reais em fixtures, logs ou Git.
- Não implementar primitivas criptográficas próprias; não confundir digest do PDF com digest dos atributos CMS. Evitar double hashing. Validar assinatura retornada e certificado esperado antes de concluir.
- Não autorizar assinatura arbitrária; vincular JWS a instância, usuário, tenant, transação, documento, certificado, algoritmo, digest, expiração e nonce; consumo atômico online e consentimento nativo explícito. Negar por padrão.
- Isolamento tenant em consultas, filas, storage, webhooks e download; validar autorização no servidor. Idempotência, concorrência, estados e recuperação explícitos.
- Não desabilitar TLS, verificação de cadeia, revogação ou validação por conveniência; distinguir erro de rede de revogação. Restringir SSRF em downloads OCSP/CRL e URLs externas.
- Native Messaging: validar schemas, tamanho, origem e comandos; stdout apenas protocolo, logs redigidos em stderr. Chaves públicas de instância precisam de bootstrap confiável e revogação.
- Bird ID opcional BYOC; não publicar credenciais nem componentes proprietários, não presumir gratuidade ou aprovação contratual. Testes autenticados somente com ambiente autorizado.
- Sem telemetria obrigatória. Minimizar dados pessoais; tratar PDFs como entradas não confiáveis. Não afirmar conformidade ICP-Brasil com base apenas em assinatura criptográfica válida.

## Definition of done
Requisito rastreado, código e testes revisáveis, contratos versionados, erros tratados, documentação atualizada, ausência de segredos, licença verificada, resultados de testes registrados. Gate de hardware/ITI/fornecedor permanece pendente quando não testado. Nenhum stub deve retornar sucesso falso.

## Ordem inicial
Protocol → Engine PoC → Desktop → Extension → SDK JS → Hub → Bird ID (gate contratual) → SDK PHP → infraestrutura → beta. Não gerar toda a aplicação de uma vez. Consulte os arquivos locais para comandos após bootstrap; atualmente não existem runtimes ou lockfiles instalados.
