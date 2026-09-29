# 🛡️ GvulStand - Sistema de Gestão de Vulnerabilidades

**GvulStand** é uma plataforma corporativa web de alta performance para **Gestão, Governança e Remediação de Vulnerabilidades de Segurança da Informação**, baseada na importação e análise analítica de relatórios de varredura do **Tenable Nessus / Tenable Security Center / Tenable.io** (CSV). O sistema foi arquitetado em estrita conformidade com as normas internacionais **ISO/IEC 27001:2022 / ISO/IEC 27002:2022** (Controle 8.8 – Gestão de Vulnerabilidades Técnicas e Tratamento de Riscos) e **ISO 9001:2015** (Melhoria Contínua da Qualidade – Ciclo PDCA).

---

## 🎯 Principais Funcionalidades

### 1. Autenticação & Controle de Acesso Baseado em Papéis (RBAC)
- **Credenciais de Fábrica (Seed Idempotente):**
  - **Administrador Geral:** `Admin` / `Admin` (Acesso irrestrito a configurações, usuários, parâmetros e exclusões)
  - **Analista de Segurança:** `analista` / `analista` (Acesso operacional: scans, tratativas, planos de ação e relatórios)
  - **Auditor ISO:** `auditor` / `auditor` (Acesso estritamente somente leitura a dashboards, inventários e relatórios; bloqueio HTTP 403 para tratativas)
- **Autenticação Local:** Tokens JWT seguros (`HS256`, validade configurável de 24h) com senhas criptografadas via **bcrypt** com salt dinâmico.
- **Integração Nativa com Active Directory / LDAP:**
  - Suporte a conexões LDAP padrão (porta 389), LDAPS seguro com SSL (porta 636) e StartTLS.
  - Cadastro de contas corporativas vinculadas via `sAMAccountName`, com importação automática de Nome Completo e E-mail.
  - Teste de conectividade em tempo real e busca de usuários com credenciais de bind protegidas por criptografia simétrica.
- **Proteções de Segurança:**
  - Criptografia em repouso com **Fernet (AES-128-CBC + HMAC-SHA256)** para credenciais de serviço salvas no banco.
  - Proteção de integridade contra autoexclusão ou exclusão do último administrador ativo.
  - Alteração de senha individual pelo próprio usuário autenticado.

### 2. Governança e Métricas Normativas (ISO/IEC 27001 & ISO 9001)
- **Índice de Postura de Risco ISO 27001 (Controle 8.8):** Cálculo ponderado de exposição de risco da organização dividido pela quantidade de hosts únicos ativos:
  $$\text{Índice de Risco} = \frac{(Crit \times 10.0) + (High \times 5.0) + (Med \times 2.0) + (Low \times 0.5)}{\max(1, \text{Total de Hosts Únicos})}$$
- **Taxa de Eficácia de Remediação ISO 9001 (Ciclo PDCA Global):** Acompanhamento do percentual de vulnerabilidades remediadas em relação ao total de apontamentos acionáveis.
- **Ciclo de Vida Formal de Tratamento:**
  - Estados normativos: `Open` (Aberta), `In_Action_Plan` (Em Plano de Ação), `In_Remediation` (Em Correção Técnica), `Accepted_Risk` (Risco Aceito Formalmente) e `Remediated` (Remediada).
  - Justificativa/nota de auditoria obrigatória em qualquer alteração de status.
- **Trilha de Auditoria Imutável (`VulnerabilityTreatmentHistory`):** Registro histórico cronológico completo de cada tratativa com usuário responsável (`changed_by_username`), data/hora UTC (`changed_at`), notas de justificativa e status anterior/posterior.

### 3. Dashboard Executivo & Painel de KPIs
- **Cards de Severidade Quantitativa:** Contadores de vulnerabilidades Críticas, Altas, Médias, Baixas e Informativas, com contagem deduplicada de CVEs únicos.
- **Governança do Ciclo de Vida:** Totalizadores por status de tratamento cruzados por nível de criticidade.
- **Tenable Vulnerability Priority Rating (VPR):** Distribuição analítica nas faixas 9.0–10.0 (Crítica), 7.0–8.9 (Alta), 4.0–6.9 (Média) e 0.0–3.9 (Baixa).
- **Aging de Vulnerabilidades (Idade dos Apontamentos):**
  - Visão Macro: 0–30 dias (No SLA), 31–60 dias (Atenção), 61–90 dias (Atrasado) e >90 dias (Débito Técnico Crítico).
  - Matriz de Aging Detalhada em 6 faixas temporais por criticidade: 0–7, 8–14, 15–30, 31–60, 61–90 e >90 dias.
- **Progresso de SLA:** Itens dentro do prazo (*Meeting*) vs. fora do prazo (*Breached*) com base nos limites definidos por criticidade.
- **Scan Health & Cobertura de Credenciais:** Mapeamento da qualidade da varredura por host (autenticação com sucesso, acesso insuficiente, falha de autenticação, erro intermitente ou varredura sem credenciais).
- **Vetores de Exploração:** Detecção de vulnerabilidades exploradas por malware ativo, exploits em frameworks públicos (Metasploit, CANVAS, Core Impact, D2 Elliot, ExploitHub) e distinção entre vetores remotos e locais.
- **Research & Patch Advisory:** Indicador de patches oficiais disponíveis vs. pendentes de aplicação.

### 4. Inventário Geral de Hosts & Ativos do Parque
- **Visão Consolidada de Ativos:** Mapeamento completo dos hosts identificados a partir do scan mais recente de cada grupo.
- **Ficha Técnica por Ativo:** Endereço IP, Hostname, NetBIOS, Sistema Operacional, contadores individuais por severidade e **Host Risk Score** individual ponderado.
- **Estatísticas Globais do Parque:** Total de hosts, total de vulnerabilidades, médias e máximas de score de risco, hosts com apontamentos críticos e hosts com exploits conhecidos.
- **Filtros e Recursos:** Busca textual instantânea (IP, hostname, SO ou grupo), filtro rápido por nível de risco, ordenação dinâmica por qualquer coluna e paginação no servidor.
- **Rastreabilidade:** Indicação direta do Plano de Ação ativo vinculado ao host.

### 5. Gerenciador de Planos de Ação (WBS & Remediação Estruturada)
- **Estruturação de Projetos de Correção (ISO 27001 / ISO 9001):** Criação e acompanhamento de planos de ação integrados ao fluxo de sustentação técnica.
- **Tipos Flexíveis de Escopo:**
  - **Por Host (`HOST`):** Agrupa todos os apontamentos de um ativo crítico específico.
  - **Por Vulnerabilidade (`VULNERABILITY`):** Agrupa a correção de uma vulnerabilidade/plugin em todos os hosts afetados.
  - **Por Grupo de Ativos (`GROUP`):** Foco em uma unidade de negócio, datacenter ou aplicação.
  - **Customizado (`CUSTOM`):** Definição livre de escopo operacional.
  - **Matricial N:N (`MATRIX_NN`):** Associação bipartida de múltiplos hosts e múltiplos plugins em um único plano com validação estrita de pertinência relacional.
- **Estrutura Analítica de Projeto (WBS / Tarefas):**
  - Divisão do plano em tarefas sequenciais com índices de ordenação (`order_index`).
  - Atribuição de responsável individual (`assigned_user_id`), data de início e prazo de conclusão (`due_date`).
  - Fluxo de status de tarefas: `TODO`, `DOING`, `REVIEW`, `DONE`, `BLOCKED`.
  - Conclusão automatizada de plano ao concluir todas as tarefas e cálculo de percentual de progresso.
- **Vínculo Exclusivo & Regra de Precedência ISO 27001:**
  - Cada vulnerabilidade ativa pertence estritamente a um plano de ação em andamento.
  - Planos específicos de Host têm precedência sobre planos genéricos por plugin, migrando automaticamente a tratativa com registro formal de histórico.
  - Transição automática para status `In_Action_Plan` e reversão segura para `Open` em caso de exclusão ou cancelamento de planos órfãos.
- **Multi-Tagging de Governança:** Rotulação transversal por normas regulatórias e contextos de negócio (ex: `PCI-DSS`, `SOX`, `LGPD`, `Urgente`, `RedTeam`).
- **Simulação e Preview de Impacto (`/action-plans/preview-impact`):** Cálculo prévio de redução de risco e quantidade de hosts/apontamentos contemplados antes da criação do plano.

### 6. Motor Comparativo Antes vs. Depois (Eficácia & Diff PDCA ISO 9001)
- **Seleção Livre de Scans:** Cruzamento analítico entre qualquer par de varreduras de um grupo de ativos (Scan Baseline / Antes vs. Scan de Reteste / Depois).
- **Cruzamento Quádruplo por Assinatura Única:** Identificação unívoca por `Host IP + Plugin ID + Porta + Protocolo`.
- **Triagem de Resultados:**
  - 🟢 **Vulnerabilidades Remediadas:** Presentes no Baseline e eliminadas no Reteste (comprovação de eficácia).
  - 🟡 **Vulnerabilidades Persistentes:** Presentes em ambas as varreduras (cobrança de prazos de SLA e reincidência).
  - 🔴 **Novas Vulnerabilidades / Regressões:** Ausentes no Baseline e detectadas no Reteste.
- **Métricas Matemáticas Consolidadas:** Cálculo em tempo real da **Taxa de Resolução (%)** e da **Redução Líquida de Risco (%)**.

### 7. Top 100 Vulnerabilidades Críticas & Top 20 Hosts com Exploits
- **Top 100 Críticas:** Priorização por disponibilidade de exploit público, CVSS v3 e volume de ativos atingidos, com modal técnico detalhado da solução oficial e listagem completa de hosts/portas afetados.
- **Top 20 Hosts com Exploits:** Destaque dos ativos de altíssimo risco que possuem exploração pública confirmada em frameworks (Metasploit, CANVAS, Core Impact, D2 Elliot, ExploitHub).

### 8. Central de Relatórios Executivos & Auditoria (3 Modelos + PDF)
- **Modelo 1 — Relatório Sumário Executivo (`executive_summary`):**
  - Direcionado à Diretoria e C-Level: Metadados corporativos, termômetro e tendência de risco vs. ciclo anterior.
  - **Inventário com Diagnóstico de EOL (End-of-Life):** Identificação algorítmica de sistemas operacionais descontinuados (Windows Server 2003/2008/2012, Windows 7/8/XP, CentOS 6/7/8, Ubuntu 14.04/16.04/18.04, Debian Buster/Stretch/Jessie, RHEL 5/6) e alertas de EOL iminente.
  - Top 5 vulnerabilidades de maior impacto e indicadores de SLA e MTTR (*Mean Time to Remediate*).
- **Modelo 2 — Relatório Técnico Detalhado (`technical_inventory`):**
  - Dossiê completo ativo por ativo para sustentação e infraestrutura: portas TCP/UDP, CVEs, CVSS, vetores de exploit, soluções recomendadas e evidências brutas de *Plugin Output*.
- **Modelo 3 — Relatório de Auditoria e Conformidade SLA ISO 27001 (`sla_audit`):**
  - Auditoria formal do Controle 8.8 da ISO/IEC 27001 e Ciclo PDCA da ISO 9001.
  - Aderência percentual aos prazos de SLA por criticidade, matriz de aging temporal e índice de eficiência de remediação.
  - **Trilha de Auditoria de Riscos Aceitos:** Listagem exaustiva de vulnerabilidades aceitas com notas justificativas, quem aprovou e quando.
  - Listagem de vulnerabilidades estouradas fora de SLA com cálculo de dias de atraso e plano recomendado.
- **Emissão e Exportação:** Visualização em janelas dedicadas, impressão e exportação via `@media print` A4 e geração programática de PDFs com **ReportLab** e **Matplotlib**.

### 9. Motor de Ingestão e Parser Nessus CSV Resiliente
- **Processamento de Grandes Volumes:** Processa arquivos CSV de 100 MB+ sem estouro de limite de memória (`csv.field_size_limit`).
- **Autodetecção de Delimitadores e Encodings:** Compatível com ponto e vírgula (`;`), vírgula (`,`), tabulação (`\t`) e pipe (`|`), com fallback automático para UTF-8, UTF-8-BOM, Latin-1 e CP1252.
- **Reconstrução de Quebras de Linha (Stitching Engine):** Recupera registros corrompidos por quebras de linha não escapadas em saídas de plugins (*Plugin Output*).
- **Deduplicação e Agregação Multi-CVE:** Unificação de múltiplos CVEs em um único apontamento consolidado por porta e protocolo.
- **Desacoplamento Temporal (`scan_date`):** Data da varredura independente da data de upload do arquivo.

### 10. Diagnóstico & Troubleshoot de Scans (Scan Health)
- **Identificação de Falhas de Varredura:** Mapeamento de problemas de rede e autenticação (ICMP Echo bloqueado, falha de login Windows SMB/RPC, falha SSH em Linux, negação WMI/DCOM, falta de privilégios `sudo` e scans interrompidos).
- **Recomendações Prescritivas:** Guia de ação corretiva para a equipe de infraestrutura liberar acessos antes de um reteste.

### 11. Grupos de Ativos & Hierarquia em Árvore Multinível
- **Árvore Hierárquica Multinível:** Cadastro de grupos principais, subgrupos regionais e áreas de sistemas com cálculo recursivo de caminho estrutural (ex: *Corporativo > Datacenter SP > Cluster Web*).
- **Prevenção de Referência Circular:** Bloqueio algorítmico contra dependências cíclicas em qualquer nível da árvore.
- **SLAs Customizados por Grupo:** Prazos de atendimento independentes por grupo de ativos (Crítica, Alta, Média, Baixa).
- **RBAC Granular por Grupo:** Associação de usuários com permissões específicas de tratar (`can_treat`), importar (`can_import`) e emitir relatórios (`can_author`).

### 12. Parâmetros Globais do Sistema (Administração Pontual)
- **Fuso Horário Operacional (`timezone`):** Base de referência padronizada com suporte a todos os fusos brasileiros e internacionais, relógio ao vivo (*Live Clock*) e formatação oficial com indicação de offset UTC.
- **Prazos Globais de SLA:** Configuração padrão de prazos em dias para cada criticidade com botão de propagação em massa para todos os grupos.
- **Classificação e Expurgo de Falsos-Positivos (`ignored_vulnerability_ids`):**
  - Exclusão automática de Plugins ou IDs informados de todos os cálculos de dashboards, relatórios, métricas de SLA e comparativos.
  - Interface interativa com chips/tags e adição com 1 clique do plugin informativo `19506`.
  - **Simulação em Tempo Real (`preview-ignored`):** Verificação prévia da quantidade de ocorrências e hosts afetados antes de salvar as regras.

---

## 🚀 Como Executar

### Opção 1: Containers Docker com MariaDB 11.4 LTS (Recomendado para Produção)

```bash
# 1. Clonar o repositório
git clone https://github.com/lluizrreis/GvulStand_Dev.git
cd GvulStand_Dev

# 2. Configurar o arquivo de ambiente
cp .env.example .env
# Ajuste as variáveis SECRET_KEY, MYSQL_ROOT_PASSWORD e MYSQL_PASSWORD no .env

# 3. Construir e iniciar os serviços em segundo plano
docker compose up --build -d

# 4. Acessar a aplicação no navegador:
# http://localhost:8888

# 5. Para encerrar os serviços:
docker compose down
```

### Opção 2: Execução Local Instantânea (Python 3.12 + SQLite)

```bash
# 1. Criar e ativar o ambiente virtual
python3 -m venv .venv
source .venv/bin/activate  # No Linux/macOS
# .venv\Scripts\activate   # No Windows

# 2. Instalar as dependências do backend
pip install -r backend/requirements.txt

# 3. Inicializar a aplicação (abre automaticamente o navegador)
python run_local.py
```

No Windows, utilize o menu interativo:
```cmd
start.bat
```

---

## 🔑 Credenciais Padrão Iniciais

| Usuário | Senha Padrão | Perfil de Acesso | Permissões |
| :--- | :--- | :--- | :--- |
| `Admin` | `Admin` | **Administrador Geral** | Acesso total e irrestrito (CRUD Usuários, Grupos, Scans, LDAP, Parâmetros) |
| `analista` | `analista` | **Analista de Segurança** | Operação técnica (Scans, Tratativas, Planos de Ação, Diff, Relatórios) |
| `auditor` | `auditor` | **Auditor ISO** | Visualização completa de dashboards e relatórios (Somente Leitura) |

> ⚠️ **Importante:** Altere as senhas padrão imediatamente após o primeiro acesso na tela de Gestão de Usuários ou Perfil. O sistema impede a exclusão ou inativação do último administrador ativo.

---

## 📂 Arquivos de Amostra para Testes

O diretório `samples/` contém varreduras reais formatadas no padrão Tenable Nessus para validação de fluxos:
- `samples/nessus_baseline_scan.csv` — Varredura inicial (Baseline) com vulnerabilidades críticas conhecidas (Log4Shell, EternalBlue, PHP CGI RCE, SSL desatualizado).
- `samples/nessus_retest_post_remediation.csv` — Varredura de reteste pós-remediação para validação do comparativo Antes vs. Depois e cálculo de eficácia PDCA.

Na tela de **Importar Scans**, clique em **"Baixar Modelo de CSV Nessus para Teste"** para baixar o modelo diretamente pela interface.

---

## 🧪 Testes Automatizados (Qualidade Garantida)

A aplicação conta com uma suíte de testes automatizados com **pytest**, cobrindo 100% dos fluxos de negócio críticos:

```bash
# Executar toda a suíte de testes com relatório detalhado:
pytest backend/tests -v
```

### Resumo da Cobertura de Testes (61 de 61 Aprovados - 100%):
- `test_all.py` (26 testes): Ingestão Nessus, delimitadores, quebras de linha, multi-CVE, autenticação local, RBAC de perfis e grupos, upload, cálculo de aging, diagnósticos e comparativo diff.
- `test_action_plans.py` (12 testes): Ciclo de vida de planos de ação, escopos HOST/VULN/GROUP/MATRIX_NN, precedência ISO 27001, reversão de vulnerabilidades órfãs para Open, multi-tagging e assistente wizard.
- `test_inventory.py` (1 teste): Inventário paginado de hosts, filtros de criticidade, busca textual e agregação de score de risco.
- `test_ldap.py` (6 testes): Conectividade LDAP/AD, busca por sAMAccountName, autenticação corporativa, permissões e criptografia Fernet em repouso.
- `test_parameters.py` (9 testes): Configuração de fuso horário, limites de SLA, expurgo automático de falso-positivo nos indicadores e simulação prévia de impacto.
- `test_reports.py` (7 testes): Emissão dos 3 modelos de relatórios (Sumário Executivo com EOL, Dossiê Técnico Ativo por Ativo e Auditoria SLA ISO 27001).

---

## 🏗️ Estrutura de Diretórios do Projeto

```text
gvulstand/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes_auth.py           # Autenticação JWT local e AD/LDAP, troca de senha
│   │   │   ├── routes_users.py          # Gestão de usuários (local/AD) e permissões por grupo
│   │   │   ├── routes_ldap.py           # Configuração LDAP/AD, teste de conexão e validação
│   │   │   ├── routes_parameters.py     # Fuso horário, SLAs padrão e expurgo de falso-positivo
│   │   │   ├── routes_asset_groups.py   # Hierarquia de grupos/subgrupos em árvore e SLAs
│   │   │   ├── routes_scans.py          # Upload de CSV Nessus, listagem e exclusão em cascata
│   │   │   ├── routes_dashboard.py      # Indicadores executivos, VPR, aging, top 100 e scan health
│   │   │   ├── routes_vulnerabilities.py# Inventário de hosts, listagem de vulns, tratativas e histórico
│   │   │   ├── routes_action_plans.py   # Planos de ação WBS, tarefas, tags, escopo matricial N:N
│   │   │   ├── routes_comparative.py    # Comparativo Antes vs Depois (PDCA ISO 9001)
│   │   │   └── routes_reports.py        # Modelos de relatórios executivos, técnicos e auditoria SLA
│   │   ├── services/
│   │   │   ├── parser_nessus.py         # Motor de parsing CSV resiliente (100MB+, multi-CVE)
│   │   │   ├── comparative_service.py   # Motor de diff e cálculo de resolução/redução de risco
│   │   │   ├── asset_group_service.py   # Tratamento de hierarquia em árvore e herança de grupos
│   │   │   ├── parameter_service.py     # Fusos horários, SLAs e regras de exclusão de indicadores
│   │   │   ├── scan_service.py          # Resolução de scans mais recentes por escopo
│   │   │   └── ldap_service.py          # Comunicação com Active Directory via ldap3
│   │   ├── auth.py                      # Validação de tokens JWT, hashing bcrypt e guards RBAC
│   │   ├── config.py                    # Carregamento de configurações e variáveis de ambiente
│   │   ├── crypto_utils.py              # Criptografia simétrica Fernet para segredos em repouso
│   │   ├── database.py                  # Conexão SQLAlchemy, migrações dinâmicas e seed inicial
│   │   ├── models.py                    # Modelos ORM (User, Scan, Host, Vulnerability, ActionPlan, etc.)
│   │   ├── schemas.py                   # Schemas Pydantic v2 com validação rigorosa de DTOs
│   │   ├── generate_pdf.py              # Gerador de relatórios em PDF com ReportLab e Matplotlib
│   │   └── main.py                      # App FastAPI, middlewares, inclusão de rotas e SPA server
│   ├── tests/                           # Suíte automatizada com 61 testes (pytest)
│   └── requirements.txt                 # Dependências Python do ecossistema
├── frontend/
│   └── public/
│       ├── index.html                   # Single Page Application (SPA) responsiva
│       ├── report-summary.html          # Janela de emissão: Relatório Sumário Executivo
│       ├── report-technical.html        # Janela de emissão: Relatório Técnico Detalhado
│       ├── report-sla-audit.html        # Janela de emissão: Relatório de Auditoria SLA ISO 27001
│       ├── css/
│       │   └── styles.css               # Folha de estilos, temas claro/escuro e regras de impressão A4
│       └── js/
│           ├── api.js                   # Camada de comunicação REST com interceptores JWT
│           ├── app.js                   # Controlador principal da aplicação e rotas da UI
│           └── charts.js                # Renderizador de gráficos interativos Chart.js
├── data/
│   ├── uploads/                         # Armazenamento de arquivos CSV importados
│   └── gvulstand.db                     # Banco de dados SQLite local
├── samples/                             # CSVs de varredura Nessus para testes e demonstrações
├── docker-compose.yml                   # Orquestrador dos containers MariaDB 11.4 e Web App
├── Dockerfile                           # Especificação de build da imagem de produção
├── .env.example                         # Modelo de configuração de variáveis de ambiente
├── run_local.py                         # Script de inicialização em modo de desenvolvimento
└── start.bat                            # Script de inicialização facilitada para Windows
```

---

## ⚙️ Variáveis de Ambiente (`.env`)

Crie o arquivo `.env` a partir do modelo `.env.example`:

```env
# Identificação da Aplicação
APP_NAME="GvulStand - Vulnerability Management System"

# Chave Criptográfica Secreta (Altere para produção via: openssl rand -hex 32)
SECRET_KEY="sua-chave-secreta-extremamente-segura-e-aleatoria"
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Credenciais Iniciais do Administrador Geral
DEFAULT_ADMIN_USERNAME="Admin"
DEFAULT_ADMIN_PASSWORD="SuaSenhaSeguraAqui"
DEFAULT_ADMIN_EMAIL="admin@empresa.com.br"

# Banco de Dados SQLite (Desenvolvimento Local):
DATABASE_URL="sqlite:///./data/gvulstand.db"

# Banco de Dados MariaDB (Produção Conteinerizada via Docker Compose):
MYSQL_ROOT_PASSWORD=DefinaSenhaRootForteAqui
MYSQL_DATABASE=gvulstand
MYSQL_USER=gvuluser
MYSQL_PASSWORD=DefinaSenhaUsuarioForteAqui
```

---

## 🔌 Referência da API REST

Prefixo base: `/api` (com compatibilidade `/api/v1` para módulos operacionais).

| Módulo | Método | Endpoint | Perfil Mínimo | Descrição |
| :--- | :---: | :--- | :---: | :--- |
| **Auth** | `POST` | `/api/auth/login` | Público | Autenticação (usuários locais ou AD/LDAP) gerando token JWT |
| **Auth** | `POST` | `/api/auth/login-form` | Público | Endpoint compatível com Swagger UI OAuth2 |
| **Auth** | `GET` | `/api/auth/me` | Autenticado | Retorna os dados do usuário autenticado na sessão |
| **Auth** | `POST` | `/api/auth/change-password` | Autenticado | Permite ao usuário logado alterar sua própria senha local |
| **Users** | `GET` | `/api/users` | Admin | Listagem completa de usuários com permissões por grupo |
| **Users** | `POST` | `/api/users` | Admin | Cadastro de novo usuário (manual local ou vinculado ao AD) |
| **Users** | `GET` | `/api/users/{id}` | Admin | Detalhes cadastrais de um usuário específico |
| **Users** | `PUT` | `/api/users/{id}` | Admin | Atualização de perfil, status e permissões de grupo |
| **Users** | `DELETE` | `/api/users/{id}` | Admin | Exclusão de usuário (proteção ao último admin) |
| **LDAP** | `GET` | `/api/ldap/config` | Admin | Consulta parâmetros da integração LDAP (senha mascarada) |
| **LDAP** | `PUT` | `/api/ldap/config` | Admin | Atualiza configurações de host, portas, SSL e credenciais |
| **LDAP** | `POST` | `/api/ldap/test` | Admin | Testa conectividade e autenticação com o servidor AD |
| **LDAP** | `GET` | `/api/ldap/validate-user` | Admin | Valida conta no AD por sAMAccountName trazendo dados |
| **Params** | `GET` | `/api/parameters` | Autenticado | Retorna fuso horário, SLAs padrão e IDs desconsiderados |
| **Params** | `PUT` | `/api/parameters` | Admin | Atualiza fuso horário, limites de SLA e lista de falso-positivo |
| **Params** | `GET` | `/api/parameters/timezones` | Autenticado | Lista fusos horários disponíveis com offsets formatados |
| **Params** | `POST` | `/api/parameters/preview-ignored` | Autenticado | Simula impacto dos IDs de falso-positivo antes de salvar |
| **Params** | `POST` | `/api/parameters/apply-slas-to-all-groups` | Admin | Propaga os SLAs padrão para todos os grupos de ativos |
| **Groups** | `GET` | `/api/asset-groups` | Autenticado | Lista grupos de ativos com métricas e hierarquia em árvore |
| **Groups** | `POST` | `/api/asset-groups` | Analista/Admin | Cria novo grupo de ativos ou subgrupo hierárquico |
| **Groups** | `GET` | `/api/asset-groups/{id}` | Autenticado | Detalhes do grupo, métricas consolidadas e SLAs |
| **Groups** | `PUT` | `/api/asset-groups/{id}` | Analista/Admin | Atualiza informações, grupo pai e limites de SLA |
| **Groups** | `DELETE` | `/api/asset-groups/{id}` | Admin | Exclui grupo de ativos e registros associados em cascata |
| **Scans** | `GET` | `/api/scans` | Autenticado | Lista varreduras importadas com filtros por grupo e tipo |
| **Scans** | `POST` | `/api/scans/upload` | Analista/Admin | Importa relatório Nessus CSV (baseline ou reteste) |
| **Scans** | `GET` | `/api/scans/{id}` | Autenticado | Retorna detalhes do scan e totais consolidados |
| **Scans** | `DELETE` | `/api/scans/{id}` | Admin | Exclui scan, hosts e vulnerabilidades vinculadas em cascata |
| **Dashboard** | `GET` | `/api/dashboard/stats` | Autenticado | Métricas consolidadas, KPIs, aging, VPR e progresso de SLA |
| **Dashboard** | `GET` | `/api/dashboard/top-critical` | Autenticado | Top 100 vulnerabilidades críticas com contagem de hosts |
| **Dashboard** | `GET` | `/api/dashboard/top-hosts-exploits` | Autenticado | Top 20 hosts com vulnerabilidades que possuem exploits |
| **Dashboard** | `GET` | `/api/dashboard/plugin-solution/{plugin_id}` | Autenticado | Solução do fornecedor e lista de todos os hosts afetados |
| **Dashboard** | `GET` | `/api/dashboard/scan-diagnostics` | Autenticado | Diagnóstico prescritivo de integridade e falhas de scan |
| **Inventory** | `GET` | `/api/vulnerabilities/inventory` | Autenticado | Inventário paginado de hosts com risk scores e métricas |
| **Inventory** | `GET` | `/api/vulnerabilities/unique-hosts` | Autenticado | Lista resumida de hosts únicos para filtros na interface |
| **Vulns** | `GET` | `/api/vulnerabilities` | Autenticado | Listagem paginada de vulnerabilidades com múltiplos filtros |
| **Vulns** | `GET` | `/api/vulnerabilities/{id}` | Autenticado | Detalhes de um apontamento e status de plano de ação |
| **Vulns** | `PATCH` | `/api/vulnerabilities/{id}/treatment` | Analista/Admin | Atualiza tratativa com nota de auditoria obrigatória |
| **Vulns** | `GET` | `/api/vulnerabilities/{id}/treatment-history` | Autenticado | Histórico imutável de tratativas do apontamento |
| **Vulns** | `POST` | `/api/vulnerabilities/bulk-treatment` | Analista/Admin | Atualização de tratamento em lote para múltiplos itens |
| **Plans** | `GET` | `/api/action-plans` | Autenticado | Lista planos de ação com filtros por status, prioridade e tags |
| **Plans** | `GET` | `/api/action-plans/stats` | Autenticado | Estatísticas globais de planos de ação e tarefas WBS |
| **Plans** | `GET` | `/api/action-plans/assignees` | Autenticado | Lista usuários elegíveis para atribuição de tarefas |
| **Plans** | `GET` | `/api/action-plans/tags` | Autenticado | Catálogo de tags para categorização regulatória |
| **Plans** | `POST` | `/api/action-plans/tags` | Analista/Admin | Criação de nova tag de governança |
| **Plans** | `GET` | `/api/action-plans/unassigned-vulns` | Autenticado | Lista vulnerabilidades ativas ainda sem plano de ação |
| **Plans** | `GET` | `/api/action-plans/wizard/hosts` | Autenticado | Candidatos a hosts para o assistente de criação de planos |
| **Plans** | `GET` | `/api/action-plans/wizard/vulnerabilities` | Autenticado | Candidatos a plugins/CVEs para o assistente de criação |
| **Plans** | `POST` | `/api/action-plans/preview-impact` | Autenticado | Simulação de impacto e redução de risco de um plano |
| **Plans** | `GET` | `/api/action-plans/{id}` | Autenticado | Detalhes completos do plano, tarefas, tags e escopo |
| **Plans** | `POST` | `/api/action-plans` | Analista/Admin | Criação de plano com tarefas e vínculo de apontamentos |
| **Plans** | `PUT` | `/api/action-plans/{id}` | Analista/Admin | Atualização do plano, status e conclusão automatizada |
| **Plans** | `DELETE` | `/api/action-plans/{id}` | Analista/Admin | Exclui plano e reverte vulnerabilidades para Open |
| **Plans** | `POST` | `/api/action-plans/{id}/tasks` | Analista/Admin | Adiciona nova tarefa WBS ao plano de ação |
| **Plans** | `PUT` | `/api/action-plans/tasks/{task_id}` | Analista/Admin | Atualiza status da tarefa (TODO, DOING, REVIEW, DONE, BLOCKED) |
| **Plans** | `DELETE` | `/api/action-plans/tasks/{task_id}` | Analista/Admin | Remove tarefa WBS de um plano de ação |
| **Diff** | `GET` | `/api/comparative/diff` | Autenticado | Comparativo analítico entre scans (Remediadas, Persistentes, Novas) |
| **Diff** | `GET` | `/api/comparative/scans-by-group/{group_id}` | Autenticado | Lista scans disponíveis para comparação em um grupo |
| **Reports** | `GET` | `/api/reports/templates` | Autenticado | Catálogo dos 3 modelos oficiais de relatórios disponíveis |
| **Reports** | `GET` | `/api/reports/summary-data` | Autenticado | Dados estruturados para o Relatório Sumário Executivo com EOL |
| **Reports** | `GET` | `/api/reports/technical-data` | Autenticado | Dados estruturados para o Relatório Técnico Detalhado |
| **Reports** | `GET` | `/api/reports/sla-audit-data` | Autenticado | Dados estruturados para a Auditoria e Conformidade SLA |
| **Health** | `GET` | `/api/health` | Público | Verificação de disponibilidade e versão do sistema |

---

## 🛠️ Stack Tecnológica

| Camada | Tecnologia | Versão | Função na Arquitetura |
| :--- | :--- | :---: | :--- |
| **Backend Framework** | FastAPI | 0.115.0 | API REST assíncrona de alta performance com validação tipada e OpenAPI |
| **Servidor ASGI** | Uvicorn | 0.30.6 | Servidor ASGI padrão de mercado para execução do backend |
| **Camada ORM** | SQLAlchemy | 2.0.35 | Mapeamento objeto-relacional com suporte a SQLite e MariaDB/MySQL |
| **Validação de Dados** | Pydantic | 2.9.2 | Validação e serialização de DTOs baseada em Rust (Pydantic Core) |
| **Criptografia Simétrica** | Cryptography (Fernet) | 43.0.1 | Criptografia AES-128-CBC com HMAC para dados sensíveis em repouso |
| **Hashing de Senhas** | Passlib + Bcrypt | 1.7.4 / 4.0.1 | Hashing unidirecional com salt dinâmico para proteção de senhas |
| **Tokens de Acesso** | Python-Jose | 3.3.0 | Codificação, decodificação e validação de tokens JWT |
| **Integração AD / LDAP** | ldap3 | 2.9.1 | Comunicação RFC 4511 com Active Directory e OpenLDAP |
| **Geração de PDF** | ReportLab | ≥ 4.2.0 | Renderização programática de documentos PDF de alta fidelidade |
| **Gráficos para PDF** | Matplotlib | ≥ 3.9.0 | Renderização de gráficos vetoriais e rasterizados de estatísticas |
| **Manipulação PDF** | PyMuPDF | ≥ 1.24.0 | Inspeção, conversão e manipulação avançada de PDFs |
| **Banco de Produção** | MariaDB | 11.4 LTS | Banco relacional corporativo com transações ACID e charset utf8mb4 |
| **Banco Local/Dev** | SQLite | 3 | Armazenamento local rápido e sem necessidade de setup |
| **Frontend UI** | HTML5 + Vanilla JS (ES6+) | Moderno | Single Page Application rápida e responsiva sem build steps |
| **Estilização** | Tailwind CSS | 3.x CDN | Design responsivo, paleta petrol/slate e suporte a temas claro/escuro |
| **Gráficos da Interface** | Chart.js | 4.x | Gráficos interativos em canvas para KPIs, aging e comparativos |
| **Iconografia** | Lucide Icons | Última | Ícones vetoriais modernos e uniformes em toda a interface |
| **Testes Automatizados** | pytest + HTTPX | 8.3.3 / 0.27.2 | Suíte completa com 61 testes automatizados (100% de aprovação) |
| **Orquestração** | Docker & Docker Compose | v2+ | Empacotamento de containers reproduzíveis para produção |

---

## 📄 Licença e Direitos

Desenvolvido para governança cibernética, gestão de riscos e conformidade com as normas **ISO/IEC 27001** e **ISO 9001**. Todos os direitos reservados.
