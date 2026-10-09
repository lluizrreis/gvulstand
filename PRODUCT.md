# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Equipes de Segurança da Informação (SecOps, Analistas de Vulnerabilidade e Engenheiros de Segurança):** Responsáveis pela ingestão de scans, triagem técnica, priorização de vulnerabilidades críticas baseada em risco/exploits e condução dos planos de remediação.
- **Liderança de Segurança e CISOs:** Acompanham a postura executiva de risco, cumprimento de SLAs de severidade, redução da superfície de ataque e relatórios formais para auditorias e diretoria.
- **Times de Infraestrutura e TI (SysAdmins, DevOps):** Responsáveis pela aplicação de patches e correções nos ativos afetados, operando como executores nas etapas dos planos de ação.
- **Auditores de Conformidade e Governança:** Avaliam a aderência a normas (ISO 27001 e ISO 9001), verificando justificativas de riscos aceitos e trilhas imutáveis de auditoria.

## Product Purpose

O GvulStand é uma plataforma centralizada de orquestração, gestão e governança de vulnerabilidades de segurança da informação. O produto transforma dados brutos de varreduras em um ciclo contínuo e rastreável de remediação (PDCA), unindo ingestão multi-scanner, priorização orientada a risco iminente, planos de ação estruturados (WBS) e comprovação inequívoca de eficácia antes vs. depois da correção. Sucesso significa redução mensurável do risco cibernético nos ativos corporativos, cumprimento rigoroso dos prazos de SLA e conformidade auditável com normas ISO 27001 e ISO 9001.

## Positioning

Diferencia-se de simples visualizadores de relatórios ou sistemas genéricos de tickets ao fechar o ciclo de governança e auditoria de vulnerabilidades:
- Ingestão unificada flexível (upload de relatórios Nessus CSV e conectores nativos de API Tenable.io, Tenable.sc, Nessus Pro e Microsoft Defender for Endpoint / MDVM).
- Governança estrita ISO 27001 (Controle 8.8) com trilha de auditoria completa por vulnerabilidade (registro obrigatório de quem alterou, data/hora e justificativa para cada mudança de status).
- Planos de Ação PDCA e WBS com rastreabilidade matricial (N:N entre hosts, CVEs/plugins e tarefas com responsáveis e prazos).
- Motor de Eficácia & Diff comparando varreduras de linha de base (*baseline*) contra varreduras de reteste (*retest*), comprovando matematicamente a resolução ou reincidência de vulnerabilidades.

## Operating Context

- **Ambientes Corporativos Heterogêneos:** Ativos distribuídos em redes locais corporativas, DMZs, servidores de bancos de dados e ambientes em nuvem pública (AWS, Azure).
- **Formatos e Métodos de Ingestão:** Importação assíncrona de arquivos Nessus CSV com fila de processamento em segundo plano e sincronização periódica automatizada via REST API.
- **Fluxo Operacional PDCA:**
  1. *Planejar/Executar (Plan/Do):* Importação do scan baseline -> Triagem das Top 100 Críticas e Top 20 Hosts com Exploits -> Criação do Plano de Ação com tarefas WBS atribuídas.
  2. *Checar/Agir (Check/Act):* Realização de reteste pós-correção -> Execução do comparativo de Eficácia & Diff -> Atualização e auditoria do status de tratamento -> Emissão de relatórios executivos e técnicos em PDF.
- **Relatórios & Entregáveis:** Sumários executivos para liderança, relatórios técnicos detalhados e auditorias formais de SLA, gerados em formato web e PDF de alta fidelidade visual (PyMuPDF).

## Capabilities and Constraints

- **Funcionalidades Confirmadas:**
  - Painel Executivo com KPIs em tempo real, métricas de risco e gráficos interativos (Chart.js).
  - Inventário unificado de ativos/hosts com classificação por Grupo de Ativos e cálculo de risk score.
  - Catálogo de vulnerabilidades com filtros avançados por severidade, CVSS v2/v3, CVE, status de exploit disponível e malware.
  - Módulo de Planos de Ação com suporte a escopos customizados, por host, por vulnerabilidade ou matricial N:N, com tags de governança (ex: PCI-DSS, SOX).
  - Controle de Acesso RBAC com perfis distintos (admin, analyst, auditor) e controle granular de permissões por grupo de ativos (`can_treat`, `can_import`, `can_author`).
  - Autenticação local e integração corporativa LDAP / Active Directory com StartTLS/SSL.
  - Parametrizações globais: fuso horário operacional (`America/Sao_Paulo`), SLAs por severidade e lista de exclusão de falsos-positivos.
  - Geração de relatórios PDF com PyMuPDF.
  - Fila de processamento assíncrono para uploads de grandes arquivos CSV.
- **Restrições Técnicas:**
  - Stack atual: Backend FastAPI (Python 3.12), PostgreSQL 16 com SQLAlchemy, Frontend HTML5/Vanilla JS/Tailwind CSS, Nginx e Docker Compose.
  - Idioma nativo da interface e comunicações: Português do Brasil (pt-BR).
  - Criptografia de segredos de integração em repouso via Fernet.
- **Decisões em Aberto:**
  - Expansão de conectores para novos scanners adicionais no futuro (ex: Qualys, OpenVAS/Greenbone).
  - Mecanismos de notificações ativas (Webhook / Teams / Slack / E-mail) para estouro de SLA ou falha de sincronização.

## Brand Commitments

- **Nome do Produto:** GvulStand (Gestão de Vulnerabilidades / Orquestração e Correção de Vulnerabilidades).
- **Voz e Personalidade:** Técnico, corporativo, preciso, confiável, focado em alta segurança e governança executiva.
- **Identidade Visual Incumbente:** Tema escuro/claro com paleta predominante em tons Teal / Slate / Zinc e iconografia Lucide (`shield-check`, `server`, `clipboard-check`, `flame`, etc.).

## Evidence on Hand

- Amostras reais de scans de teste e baseline disponíveis em `samples/nessus_baseline_scan.csv` e `samples/nessus_retest_post_remediation.csv`.
- Bateria de testes de integração e unitários em `backend/tests/` (cobertura de relatórios, inventário, LDAP, planos de ação, parâmetros e autenticação).
- Estrutura completa de banco de dados e migrações consolidada em `backend/app/models.py`.

## Product Principles

- **Governança com Rastreabilidade Inegociável:** Nenhuma tratativa ou aceite de risco ocorre sem registro formal de autoria, data e justificativa auditável (ISO 27001).
- **Priorização Baseada em Risco Real:** Foco nos vetores de maior impacto — vulnerabilidades críticas com exploits públicos ativos e hosts de maior exposição têm precedência operacional imediata.
- **Ciclo Fechado de Remediação (PDCA):** O processo só é considerado concluído com a comprovação analítica de eficácia por meio de reteste comparativo contra a linha de base.
- **Agilidade e Confiança Operacional:** Interface responsiva, clara e focada em dados acionáveis, sem ruído visual que comprometa a tomada de decisão rápida pelo analista ou gestor.

## Accessibility & Inclusion

- Conformidade com padrões de legibilidade e contraste WCAG AA para visualização nítida de severidades, badges de status e gráficos em temas claro e escuro.
