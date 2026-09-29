# GvulStand — Documentação Técnica e Funcional

> Revisão baseada em análise completa do código-fonte. Versão 1.0 — 2026.

---

## 1. Visão Geral da Arquitetura

O GvulStand é uma SPA (Single Page Application) com backend FastAPI e banco relacional (SQLite/MariaDB). A comunicação é feita exclusivamente via REST JSON com autenticação JWT Bearer.

```
[Browser SPA]  <--REST/JSON-->  [FastAPI + Uvicorn]  <--SQLAlchemy ORM-->  [MariaDB / SQLite]
                                        |
                              [Serviços de Domínio]
                              parser_nessus.py
                              comparative_service.py
                              asset_group_service.py
                              parameter_service.py
                              scan_service.py
                              ldap_service.py
```

### Stack Tecnológica

| Camada | Tecnologia | Versão |
|---|---|---|
| Backend | FastAPI | 0.115.0 |
| Servidor ASGI | Uvicorn | 0.30.6 |
| ORM | SQLAlchemy | 2.0.35 |
| Validação | Pydantic | 2.9.2 |
| Criptografia | Cryptography (Fernet) | 43.0.1 |
| Hashing | Passlib + Bcrypt | 1.7.4 / 4.0.1 |
| JWT | Python-Jose | 3.3.0 |
| LDAP/AD | ldap3 | 2.9.1 |
| PDF | ReportLab + Matplotlib | ≥4.2.0 / ≥3.9.0 |
| Banco Produção | MariaDB | 11.4 LTS |
| Banco Dev | SQLite | 3 |
| Frontend | HTML5 + Vanilla JS ES6+ | — |
| CSS | Tailwind CSS | 3.x CDN |
| Gráficos UI | Chart.js | 4.x |
| Testes | pytest + HTTPX | 8.3.3 / 0.27.2 |

---

## 2. Modelo de Dados (ORM)

### Entidades Principais

| Modelo | Tabela | Descrição |
|---|---|---|
| `User` | `users` | Usuários locais e LDAP com RBAC (admin/analyst/auditor) |
| `AssetGroup` | `asset_groups` | Grupos de ativos com hierarquia pai/filho e SLAs |
| `UserAssetGroup` | `user_asset_groups` | Permissões granulares por grupo (can_treat, can_import, can_author) |
| `Scan` | `scans` | Varreduras importadas com contadores agregados |
| `Host` | `hosts` | Ativos identificados por scan com risk_score |
| `Vulnerability` | `vulnerabilities` | Apontamentos com ciclo de vida ISO 27001 |
| `VulnerabilityTreatmentHistory` | `vulnerability_treatment_history` | Trilha de auditoria imutável |
| `LdapConfig` | `ldap_config` | Configuração LDAP/AD (singleton id=1) |
| `SystemParameters` | `system_parameters` | Parâmetros globais (singleton id=1) |
| `ActionPlan` | `action_plans` | Planos de ação WBS |
| `ActionTask` | `action_tasks` | Tarefas/etapas dos planos |
| `ActionTaskVulnerabilityLink` | `action_task_vulnerabilities` | Vínculo N:N tarefa ↔ vulnerabilidade |
| `Tag` | `tags` | Tags de governança (PCI-DSS, SOX, LGPD...) |
| `ActionPlanTagLink` | `action_plan_tags` | Vínculo N:N plano ↔ tag |
| `ActionPlanHost` | `action_plan_hosts` | Hosts do escopo matricial MATRIX_NN |
| `ActionPlanPlugin` | `action_plan_plugins` | Plugins do escopo matricial MATRIX_NN |

### Ciclo de Vida de Vulnerabilidade (treatment_status)

```
Open → In_Action_Plan → In_Remediation → Remediated
                    ↘ Accepted_Risk
```

Toda transição exige nota de auditoria obrigatória e gera registro em `VulnerabilityTreatmentHistory`.

---

## 3. Módulos e Funcionalidades

### 3.1 Autenticação e RBAC (`routes_auth.py`, `auth.py`)

- JWT HS256 com expiração configurável (padrão 1440 min)
- Senhas com bcrypt + salt dinâmico
- Três perfis: `admin`, `analyst`, `auditor`
- Guard `require_admin`, `require_analyst_or_admin`, `require_roles(*roles)`
- Permissões granulares por grupo: `can_treat`, `can_import`, `can_author`
- Expansão recursiva de subgrupos no RBAC (`expand_descendant_group_ids`)
- Proteção: não permite excluir/inativar o último admin ativo

### 3.2 Integração LDAP/AD (`routes_ldap.py`, `ldap_service.py`)

- Suporte a LDAP (389), LDAPS (636) e StartTLS
- Bind com credenciais criptografadas via Fernet (AES-128-CBC + HMAC-SHA256)
- Busca por `sAMAccountName` com importação de `displayName` e `mail`
- Teste de conectividade em tempo real
- Autenticação dual: tenta local primeiro, depois AD

### 3.3 Parser Nessus CSV (`parser_nessus.py`)

Motor resiliente de ingestão com as seguintes capacidades:

- Suporte a arquivos 100MB+ (`csv.field_size_limit(sys.maxsize)`)
- Autodetecção de delimitadores: `;`, `,`, `\t`, `|`
- Autodetecção de encoding: UTF-8, UTF-8-BOM, Latin-1, CP1252
- **Stitching Engine**: reconstrói registros com quebras de linha não escapadas em Plugin Output
- Deduplicação por chave `(host_ip, plugin_id, port, protocol)`
- Agregação multi-CVE por ocorrência
- Mapeamento flexível de cabeçalhos via `HEADER_MAP` com aliases
- Normalização de severidade (Critical/High/Medium/Low/Info)
- Parse seguro de CVSS (suporte a inteiros escalados: `75` → `7.5`)
- Extração de exploits por framework (Metasploit, CANVAS, Core, D2 Elliot, ExploitHub, Malware)
- Cálculo de `risk_score` por host: `(Crit×10) + (High×5) + (Med×2) + (Low×0.5) + (ExploitCrit×5)`

### 3.4 Dashboard Executivo (`routes_dashboard.py`)

Todos os indicadores usam **exclusivamente o scan mais recente** de cada grupo:

- **Índice de Risco ISO 27001**: `(Crit×10 + High×5 + Med×2 + Low×0.5) / max(1, hosts_únicos)`
- **Eficácia de Remediação ISO 9001**: `(Remediadas / Total_Acionáveis) × 100`
- Aging em 4 faixas macro (0-30, 31-60, 61-90, >90 dias)
- Matriz de aging detalhada em 6 faixas por severidade
- Distribuição VPR (9-10, 7-8.9, 4-6.9, 0-3.9)
- Progresso de SLA por severidade (meeting vs. breached)
- Scan Health por IP único (auth_success, insufficient_access, auth_failure, intermittent, no_credentials)
- Vetores de exploração (malware, remote, local, framework)
- Patch Advisory (missing vs. applied)
- CVEs únicos dedupados por severidade
- Breakdown de tratativas por status × severidade
- Top 100 vulnerabilidades críticas (ordenadas por exploit > CVSS > hosts afetados)
- Top 20 hosts com exploits
- Drill-down por plugin: solução oficial + todos os hosts afetados

### 3.5 Diagnóstico de Scans (`routes_dashboard.py` — `/scan-diagnostics`)

Dicionário de 9 plugins de erro mapeados:

| Plugin ID | Categoria | Problema |
|---|---|---|
| 1102 | Rede/ICMP | Falha de Ping ICMP |
| 10180 | Rede/ICMP | Falha no teste de ping |
| 26917 | Scan Incompleto | Scan abortado/interrompido |
| 24786 | Autenticação Windows | Falha SMB/RPC |
| 12650 | Autenticação SSH | Falha de login SSH |
| 102095 | Permissão/Escalação | Sudo necessário |
| 102094 | Permissão/Escalação | Sudo não configurado |
| 104410 | Autenticação Windows | WMI negado |
| 21745 | Autenticação Geral | Checagens locais não executadas |

### 3.6 Inventário de Hosts (`routes_vulnerabilities.py`)

- Paginação server-side com filtros: busca textual, severidade, grupo
- Ordenação dinâmica por qualquer coluna
- Estatísticas globais: total_hosts, avg/max risk_score, hosts_with_critical, hosts_with_exploits
- Vínculo com plano de ação ativo por host

### 3.7 Gestão de Vulnerabilidades (`routes_vulnerabilities.py`)

- Listagem paginada com 10+ filtros combinados
- Tratamento individual com nota obrigatória e registro de auditoria
- Bulk treatment (atualização em lote) com histórico individual por vulnerabilidade
- Histórico imutável de tratativas ordenado por data decrescente
- Flag `is_ignored_in_indicators` para falsos-positivos

### 3.8 Planos de Ação (`routes_action_plans.py`)

Cinco tipos de escopo com validação relacional estrita:

| Escopo | Descrição |
|---|---|
| `HOST` | Todas as vulns de um host específico |
| `VULNERABILITY` | Um plugin em todos os hosts afetados |
| `GROUP` | Vulns críticas/altas de um grupo |
| `CUSTOM` | Escopo livre sem validação relacional |
| `MATRIX_NN` | N hosts × M plugins com validação bipartida |

**Regras de negócio críticas:**
- Planos HOST têm precedência sobre planos VULNERABILITY (migração automática com histórico)
- Ao concluir tarefa (DONE): vulnerabilidades → `Remediated`
- Ao iniciar tarefa (DOING): vulnerabilidades → `In_Remediation`
- Ao cancelar/excluir plano: vulnerabilidades órfãs → `Open`
- Auto-conclusão do plano quando todas as tarefas estão DONE
- Sincronização automática ao importar novo scan (recorrência, remediação, reabertura)

### 3.9 Motor Comparativo PDCA (`comparative_service.py`)

- Chave única: `(host_ip, plugin_id, port, protocol)`
- Classifica em: REMEDIATED, PERSISTING, NEW
- Calcula Taxa de Resolução (%) e Redução Líquida de Risco (%)
- Exclui severidade Info/None dos cálculos
- Aplica exclusão de falsos-positivos configurados

### 3.10 Relatórios (`routes_reports.py`)

Três modelos HTML com `@media print` A4 + geração PDF via ReportLab:

| Modelo | Público-alvo | Conteúdo |
|---|---|---|
| `executive_summary` | Diretoria / C-Level | KPIs, tendência de risco, EOL de SOs, Top 5 vulns, MTTR |
| `technical_inventory` | Infraestrutura / SOC | Dossiê por ativo: portas, CVEs, CVSS, exploits, Plugin Output |
| `sla_audit` | Auditores ISO | Conformidade SLA, aging, riscos aceitos, trilha de auditoria |

**Diagnóstico de EOL** detecta algoritmicamente: Windows Server 2003/2008/2012, Windows 7/8/XP, CentOS 6/7/8, Ubuntu 14.04/16.04/18.04, Debian Buster/Stretch/Jessie, RHEL 5/6.

### 3.11 Grupos de Ativos (`routes_asset_groups.py`, `asset_group_service.py`)

- Hierarquia multinível pai/filho com cálculo recursivo de caminho
- Prevenção de referência circular
- SLAs customizados por grupo (Critical/High/Medium/Low em dias)
- Propagação em massa de SLAs globais para todos os grupos
- RBAC granular por grupo

### 3.12 Parâmetros Globais (`routes_parameters.py`, `parameter_service.py`)

- Fuso horário operacional com relógio ao vivo
- SLAs padrão globais por severidade
- Lista de IDs ignorados nos indicadores (falsos-positivos)
- Simulação prévia de impacto antes de salvar exclusões (`preview-ignored`)

---

## 4. Segurança

| Mecanismo | Implementação |
|---|---|
| Autenticação | JWT HS256, expiração configurável |
| Senhas | bcrypt com salt dinâmico |
| Credenciais LDAP em repouso | Fernet (AES-128-CBC + HMAC-SHA256) |
| RBAC | Guards por role + permissões por grupo |
| Proteção de integridade | Bloqueio de exclusão do último admin |
| Nota de auditoria | Obrigatória em toda alteração de tratativa |
| Trilha imutável | `VulnerabilityTreatmentHistory` com changed_by + changed_at |

---

## 5. Testes Automatizados

61 testes pytest com 100% de aprovação distribuídos em 6 arquivos:

| Arquivo | Testes | Cobertura |
|---|---|---|
| `test_all.py` | 26 | Parser, auth, RBAC, upload, aging, diff |
| `test_action_plans.py` | 12 | Ciclo de vida de planos, escopos, precedência |
| `test_inventory.py` | 1 | Inventário paginado, filtros, risk score |
| `test_ldap.py` | 6 | LDAP/AD, Fernet, autenticação corporativa |
| `test_parameters.py` | 9 | Fuso horário, SLAs, falso-positivo, simulação |
| `test_reports.py` | 7 | 3 modelos de relatório, EOL, auditoria SLA |

---

## 6. Estrutura de Diretórios

```
gvulstand/
├── backend/app/
│   ├── api/              # 11 módulos de rotas FastAPI
│   ├── services/         # 6 serviços de domínio
│   ├── models.py         # 16 modelos ORM SQLAlchemy
│   ├── schemas.py        # DTOs Pydantic v2
│   ├── auth.py           # JWT, bcrypt, guards RBAC
│   ├── database.py       # Engine, sessão, init_db, seed
│   ├── config.py         # Variáveis de ambiente
│   ├── crypto_utils.py   # Fernet para segredos em repouso
│   ├── generate_pdf.py   # ReportLab + Matplotlib
│   └── main.py           # App FastAPI, middlewares, SPA server
├── frontend/public/
│   ├── index.html        # SPA principal
│   ├── report-*.html     # 3 janelas de relatório
│   ├── css/styles.css    # Temas claro/escuro, @media print A4
│   └── js/               # api.js, app.js, charts.js
├── data/
│   ├── uploads/          # CSVs importados
│   └── gvulstand.db      # SQLite local
├── samples/              # CSVs de teste Nessus
├── docker-compose.yml
├── Dockerfile
├── run_local.py
└── start.bat
```

---

---

## 7. Pontos de Melhoria Identificados

### 7.1 Segurança

**[CRÍTICO] SECRET_KEY hardcoded no `.env` de exemplo**
- O arquivo `.env.example` contém uma chave secreta de exemplo fraca. Em produção, a rotação de chave invalida todos os tokens ativos sem aviso ao usuário.
- Melhoria: implementar rotação de chave com período de graça (dual-key validation) e forçar geração via `openssl rand -hex 32` no primeiro boot.

**[ALTO] Ausência de rate limiting no endpoint de login**
- `POST /api/auth/login` não possui proteção contra brute-force.
- Melhoria: adicionar `slowapi` ou middleware de rate limiting (ex: 5 tentativas/minuto por IP).

**[ALTO] Tokens JWT sem revogação (blacklist)**
- Não há mecanismo de logout real; o token permanece válido até expirar.
- Melhoria: implementar blacklist de tokens em Redis ou tabela `revoked_tokens` no banco.

**[MÉDIO] Uploads de CSV sem validação de tipo MIME**
- O endpoint `POST /api/scans/upload` aceita qualquer arquivo sem verificar o content-type real.
- Melhoria: validar magic bytes do arquivo além da extensão.

**[MÉDIO] Credenciais padrão fracas no seed**
- `Admin/Admin`, `analista/analista`, `auditor/auditor` são criadas automaticamente.
- Melhoria: forçar troca de senha no primeiro login para usuários seed, ou gerar senha aleatória exibida apenas uma vez no log de inicialização.

**[MÉDIO] Ausência de HTTPS nativo**
- A aplicação serve HTTP puro na porta 8888.
- Melhoria: adicionar configuração de TLS no Uvicorn ou documentar obrigatoriedade de proxy reverso (nginx/traefik) com certificado.

**[BAIXO] Logs de autenticação sem estrutura**
- Falhas de login não são registradas de forma estruturada para SIEM.
- Melhoria: emitir eventos JSON estruturados (IP, username, timestamp, resultado) para integração com Splunk/Elastic.

---

### 7.2 Qualidade de Código e Arquitetura

**[ALTO] Lógica de negócio pesada dentro das rotas**
- `routes_dashboard.py` contém ~400 linhas de lógica de cálculo diretamente no handler.
- Melhoria: extrair para `services/dashboard_service.py` seguindo o padrão já adotado em `comparative_service.py`.

**[ALTO] Migrações de schema manuais em `database.py`**
- O `init_db()` usa `ALTER TABLE` raw com verificação manual de colunas. Frágil e não versionado.
- Melhoria: adotar **Alembic** para migrações versionadas e reversíveis.

**[MÉDIO] N+1 queries em `routes_dashboard.py`**
- O loop `for g in groups` dentro de `get_dashboard_stats` executa uma query por grupo de ativos.
- Melhoria: consolidar em uma única query com `GROUP BY asset_group_id`.

**[MÉDIO] `generate_pdf.py` usa dados estáticos de exemplo**
- Os gráficos do PDF de documentação usam valores hardcoded (`sizes = [24, 38, 52, 31]`).
- Melhoria: conectar ao banco para gerar PDF com dados reais do ambiente.

**[MÉDIO] Ausência de paginação em `list_action_plans`**
- O endpoint `GET /api/action-plans` retorna todos os planos sem limite.
- Melhoria: adicionar paginação server-side consistente com o padrão já usado em vulnerabilidades e inventário.

**[MÉDIO] `sync_action_plans_on_scan_import` carrega todos os planos ativos em memória**
- Para ambientes com muitos planos, isso pode causar degradação de performance.
- Melhoria: filtrar planos por `asset_group_id` antes de carregar tarefas e links.

**[BAIXO] Duplicação de lógica de aging**
- `calculate_aging_days` existe em `routes_vulnerabilities.py` e lógica similar está em `routes_dashboard.py`.
- Melhoria: centralizar em `services/aging_service.py` ou em um método do modelo.

**[BAIXO] `stitch_and_read_csv` usa regex simples para detectar início de registro**
- O padrão `^\s*"?\d+"?\s*` pode falhar em CSVs onde o Plugin ID não é numérico.
- Melhoria: usar `csv.Sniffer` como fallback adicional.

---

### 7.3 Operacional e DevOps

**[ALTO] Arquivos CSV de upload acumulados sem política de retenção**
- O diretório `data/uploads/` contém 200+ arquivos CSV de testes sem limpeza automática.
- Melhoria: implementar política de retenção configurável (ex: manter apenas os últimos N scans por grupo) com job de limpeza agendado.

**[MÉDIO] Ausência de health check com detalhes de dependências**
- `GET /api/health` retorna apenas status básico.
- Melhoria: incluir status do banco de dados, uso de disco e versão do schema.

**[MÉDIO] Sem configuração de CORS explícita para produção**
- O `main.py` provavelmente usa `allow_origins=["*"]` (padrão FastAPI).
- Melhoria: restringir CORS ao domínio de produção via variável de ambiente.

**[BAIXO] `start.bat` sem verificação de dependências**
- O script Windows não verifica se Python ou pip estão instalados.
- Melhoria: adicionar verificações e mensagens de erro amigáveis.

---

### 7.4 Funcionalidades Ausentes / Roadmap Sugerido

#### Prioridade Alta

**Notificações e Alertas Proativos**
- Envio de e-mail/webhook quando uma vulnerabilidade crítica estoura o SLA.
- Notificação ao responsável da tarefa quando ela é atribuída ou está próxima do vencimento.
- Integração com Microsoft Teams / Slack via webhook configurável.

**API de Integração com Scanners**
- Endpoint `POST /api/scans/import-from-tenable` para importação direta via API Tenable.io/SC sem necessidade de exportar CSV manualmente.
- Suporte a agendamento de importação automática (cron interno).

**Autenticação MFA (Multi-Factor Authentication)**
- TOTP (Google Authenticator / Authy) para usuários locais de alto privilégio (admin).
- Obrigatório para operações destrutivas (exclusão de scans, aceitação de risco em massa).

#### Prioridade Média

**Dashboard de Tendência Histórica**
- Gráfico de linha mostrando a evolução do Índice de Risco ISO 27001 ao longo do tempo (scan a scan).
- Comparação de MTTR (Mean Time to Remediate) entre períodos.

**Importação de Outros Formatos de Scanner**
- Suporte a relatórios Qualys (XML/CSV), OpenVAS (XML) e Rapid7 InsightVM (CSV).
- Motor de parser plugável com interface comum.

**Gestão de Exceções e Riscos Aceitos com Aprovação**
- Fluxo de aprovação em dois níveis para `Accepted_Risk`: analista propõe, gestor/admin aprova.
- Data de expiração para riscos aceitos com reabertura automática.

**Exportação de Dados**
- Exportação de vulnerabilidades filtradas para CSV/Excel diretamente da interface.
- Exportação do inventário de hosts para CSV.

**Comentários e Colaboração em Vulnerabilidades**
- Thread de comentários por vulnerabilidade (além da nota de auditoria única).
- Menção de usuários com notificação.

#### Prioridade Baixa

**Integração com CMDB / ITSM**
- Criação automática de tickets no ServiceNow / Jira ao criar um Plano de Ação.
- Sincronização bidirecional de status de tickets com status de tarefas WBS.

**Suporte a SSO (Single Sign-On)**
- Integração com SAML 2.0 / OAuth2 / OpenID Connect para autenticação federada.
- Suporte a Azure AD / Okta / Keycloak.

**API Pública Documentada (OpenAPI)**
- Exposição de endpoints de leitura para integração com dashboards externos (Grafana, Power BI).
- Chaves de API com escopos granulares (read-only, write).

**Módulo de Compliance Mapping**
- Mapeamento automático de vulnerabilidades para controles específicos de frameworks (PCI-DSS, LGPD, NIST CSF, CIS Controls).
- Relatório de gap analysis por framework regulatório.

**Modo Offline / PWA**
- Cache de dados do dashboard para visualização sem conexão.
- Sincronização ao reconectar.

---

## 8. Resumo Executivo de Melhorias

| Categoria | Crítico | Alto | Médio | Baixo |
|---|---|---|---|---|
| Segurança | 1 | 2 | 3 | 1 |
| Qualidade/Arquitetura | 0 | 2 | 4 | 2 |
| Operacional/DevOps | 0 | 1 | 2 | 1 |
| **Total** | **1** | **5** | **9** | **4** |

**Funcionalidades novas sugeridas:** 13 itens distribuídos em 3 níveis de prioridade.

---

*Documentação gerada por análise estática e revisão de código completa do repositório GvulStand.*
