# AGENTS.md — Guia para Agentes do GvulStand

Este documento orienta agentes de IA (e desenvolvedores) que irão **manter, criar ou editar** código no GvulStand. Leia-o por completo antes de qualquer alteração.

> Documentos complementares obrigatórios:
> - [`PRODUCT.md`](./PRODUCT.md) — propósito, usuários, capacidades e restrições do produto.
> - [`DESIGN.md`](./DESIGN.md) — sistema de design (cores, tipografia, componentes, tom visual).

---

## 1. Visão Geral

**GvulStand** é uma plataforma web de orquestração, gestão e governança de vulnerabilidades (ISO 27001 Controle 8.8 / ISO 9001 PDCA). Fluxo principal:

1. Ingestão de scans (upload Nessus CSV ou sincronização via API: Tenable.io/.sc, Nessus Pro, Microsoft Defender/MDVM, OpenVAS/GVM).
2. Triagem e priorização (severidade, CVSS, VPR, exploit/malware).
3. Planos de Ação PDCA/WBS (N:N entre hosts, plugins/CVEs e tarefas).
4. Reteste e comparativo **Baseline vs Retest** (Eficácia & Diff).
5. Relatórios executivos/técnicos/SLA em web e PDF.

**Idioma:** toda interface, mensagens de erro da API (`detail`), textos de log voltados ao usuário e documentação são em **Português do Brasil (pt-BR)**. Identificadores de código (variáveis, funções, tabelas) permanecem em inglês.

---

## 2. Stack Técnica

| Camada | Tecnologia |
|---|---|
| Backend | Python 3.12, **FastAPI** 0.115, Uvicorn, Pydantic v2 + pydantic-settings |
| ORM / Banco | **SQLAlchemy 2.0**; **PostgreSQL 16** (produção/Docker) ou **SQLite** (local/testes) |
| Autenticação | JWT (`python-jose`, HS256), `passlib[bcrypt]`, LDAP/AD (`ldap3`, StartTLS/SSL) |
| Criptografia | `cryptography` **Fernet** (segredos de integração/LDAP em repouso, chave derivada da `SECRET_KEY`) |
| Relatórios | **PyMuPDF** (`pymupdf`), `reportlab`, `matplotlib` (gráficos/fórmulas em `backend/app/pdf_assets/`) |
| Integrações | Clientes HTTP próprios (Tenable, Defender), `python-gvm` / `gvm-tools` (OpenVAS) |
| Frontend | SPA em **HTML5 + JavaScript Vanilla** (sem framework, sem bundler), **Tailwind CSS** (CLI standalone), **Chart.js 4**, **Lucide Icons** |
| Infra | Docker, Docker Compose, **Nginx** (reverse proxy TLS 80→443) |
| Testes | `pytest` + `fastapi.testclient` + `httpx`, SQLite em memória |

Todos os assets do frontend (fontes, Chart.js, Lucide) são **locais/offline** (ambiente air‑gapped). **Nunca** adicione CDNs externos; use `scripts/download_assets.py` para vendorizar novas dependências em `frontend/public/vendor/`.

---

## 3. Estrutura do Repositório

```
gvulstand/
├── AGENTS.md / PRODUCT.md / DESIGN.md   # Guias (agentes, produto, design)
├── Dockerfile / docker-compose.yml       # Containers: postgres, web, nginx
├── nginx.conf                            # Proxy reverso HTTPS -> gvulstand_app:8000
├── tailwind.config.js / tailwindcss      # Config + binário standalone do Tailwind (não versionado)
├── .env / .env.example                   # Variáveis de ambiente (.env NUNCA versionado)
├── backend/
│   ├── requirements.txt
│   ├── migrate_to_postgres.py            # Migração SQLite -> PostgreSQL
│   ├── app/
│   │   ├── main.py                       # App FastAPI, routers, lifespan (worker + scheduler), SPA
│   │   ├── config.py                     # Settings (pydantic-settings) + BASE_DIR/DATA_DIR/UPLOADS_DIR
│   │   ├── database.py                   # Engine, SessionLocal, get_db, init_db (migrações leves + seed admin)
│   │   ├── models.py                     # Modelos SQLAlchemy
│   │   ├── schemas.py                    # Schemas Pydantic (request/response)
│   │   ├── auth.py                       # JWT, hash de senha, RBAC (require_admin, require_roles...)
│   │   ├── crypto_utils.py               # encrypt/decrypt Fernet (safe_encrypt_secret / safe_decrypt_secret)
│   │   ├── generate_pdf.py               # Documentação técnica em PDF
│   │   ├── pdf_assets/                   # Imagens de gráficos/fórmulas usadas nos PDFs
│   │   ├── api/routes_*.py               # Routers por domínio
│   │   └── services/
│   │       ├── parser_nessus.py          # Parser Nessus CSV
│   │       ├── scan_service.py           # Persistência de scans/hosts/vulns
│   │       ├── comparative_service.py    # Motor Baseline vs Retest
│   │       ├── parameter_service.py      # Parâmetros globais (SLA, timezone, exclusões)
│   │       ├── asset_group_service.py    # Grupos de ativos / permissões
│   │       ├── ldap_service.py           # LDAP/AD
│   │       ├── job_queue/                # Fila assíncrona (worker.py, job_processor.py)
│   │       └── integrations/             # tenable_client, defender_client, openvas_client, sync_engine, scheduler
│   └── tests/                            # Testes pytest (test_*.py)
├── frontend/
│   ├── src/input.css                     # Fonte do Tailwind
│   └── public/                           # Servido em /static e como SPA
│       ├── index.html                    # SPA principal (todas as telas)
│       ├── js/api.js                     # Cliente HTTP (objeto API, token JWT em localStorage)
│       ├── js/app.js                     # Lógica de telas/estado (arquivo grande)
│       ├── js/charts.js                  # Gráficos Chart.js
│       ├── css/                          # tailwind.min.css (gerado), styles.css, fonts.css
│       ├── vendor/                       # chart.min.js, lucide.min.js
│       └── report-*.html                 # Templates de relatórios web
├── scripts/                              # build_css.sh, download_assets.py (ignorado no git)
├── samples/                              # CSVs Nessus de exemplo (baseline/retest)
├── data/                                 # SQLite, uploads, dumps (NÃO versionado)
└── .agent/ / .gemini/ / .impeccable/     # Skills e configuração de agentes (skill "impeccable" para UI)
```

> [!WARNING]
> `frontend/public/static/` contém cópias legadas de arquivos. O mount `/static` aponta para `frontend/public/`, portanto `/static/js/app.js` → `frontend/public/js/app.js`. **Edite sempre os arquivos em `frontend/public/` (js/, css/, index.html)**, não as cópias em `frontend/public/static/`.

---

## 4. Execução do Ambiente

### Docker (padrão)
```bash
cp .env.example .env            # e preencha SECRET_KEY, POSTGRES_PASSWORD, DEFAULT_ADMIN_*
docker volume create gvulstand_postgres_data   # volume é "external: true"
docker compose up -d --build
```
- `web` roda `uvicorn --reload` com `backend/app`, `backend/tests` e `frontend` montados como volume → alterações refletem sem rebuild.
- Alterações em `requirements.txt` ou `Dockerfile` exigem `docker compose up -d --build web`.
- Nginx gera certificado autoassinado (`nginx.crt`/`nginx.key`) se não existir. Acesso: `https://localhost`.
- Logs: `docker logs -f gvulstand_app`.

### Local (sem Docker)
```bash
source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && uvicorn app.main:app --reload --port 8000
```
Sem `DATABASE_URL`, usa SQLite em `data/gvulstand.db`.

### Variáveis de ambiente principais
`SECRET_KEY`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `DATABASE_URL`, `DEFAULT_ADMIN_USERNAME`, `DEFAULT_ADMIN_PASSWORD`, `DEFAULT_ADMIN_EMAIL`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_PORT`.

> [!CAUTION]
> Alterar a `SECRET_KEY` invalida todos os JWTs **e torna ilegíveis os segredos já criptografados** (Fernet derivado dela) de integrações e LDAP.

---

## 5. Testes

```bash
# Local
cd backend && ../.venv/bin/pytest -q tests/
# Docker
docker exec -it gvulstand_app pytest -q /app/backend/tests
```
- Os testes usam **SQLite em memória** com `StaticPool` e `app.dependency_overrides[get_db]` (ver `tests/test_all.py`).
- Toda nova funcionalidade/correção de backend deve vir acompanhada de teste em `backend/tests/test_<dominio>.py`.
- Os testes geram arquivos em `data/uploads/` — isso é esperado e ignorado pelo git.
- Garanta que o código funcione **tanto em SQLite quanto em PostgreSQL** (evite SQL específico de um dialeto sem fallback).

---

## 6. Convenções de Backend

### API
- Prefixo base: `settings.API_V1_STR` = **`/api`**. Cada domínio tem seu `routes_<dominio>.py` com `APIRouter(prefix="/<recurso>", tags=["<Descrição pt-BR>"])`, registrado em `main.py`.
- Health check: `GET /api/health`. Docs OpenAPI: `/docs`.
- Rotas que não começam com `api` caem no fallback da SPA (`serve_spa`) — **registre novos routers antes** do catch‑all.
- Erros: `HTTPException(status_code=..., detail="Mensagem em pt-BR")`.
- Request/response sempre tipados via schemas em `schemas.py` (Pydantic v2, `model_config = ConfigDict(from_attributes=True)` para ORM).
- Lógica de negócio pesada vai em `services/`, não nos routers.

### Autenticação e RBAC
- Perfis: `admin`, `analyst`, `auditor`. Permissões granulares por Grupo de Ativos (`UserAssetGroup`: `can_treat`, `can_import`, `can_author`).
- Use as dependências de `auth.py`: `get_current_user`, `require_admin`, `require_roles(...)`, `require_analyst_or_admin`.
- Toda rota nova **deve** exigir autenticação, salvo justificativa explícita. Respeite o escopo de grupos de ativos do usuário ao filtrar dados.
- Usuários podem ser `auth_type = local | ldap`.

### Banco de Dados e Migrações
- **Não há Alembic.** `Base.metadata.create_all` cria tabelas novas; colunas novas em tabelas existentes devem ser adicionadas como **migração leve idempotente em `init_db()`** (`database.py`), usando `inspect(engine)` para checar existência antes do `ALTER TABLE`, compatível com SQLite e PostgreSQL.
- Ao alterar `models.py`, atualize também `schemas.py`, a migração em `init_db()` e, se aplicável, `migrate_to_postgres.py`.
- Sessões via `Depends(get_db)`. Em tarefas de background, crie `SessionLocal()` e feche em `finally`.

### Governança / Auditoria (crítico)
- Toda mudança de status de tratamento de vulnerabilidade **deve** gerar registro em `VulnerabilityTreatmentHistory` (quem, quando, status anterior/novo, justificativa). Nunca contorne essa trilha.
- Riscos aceitos/falsos‑positivos exigem justificativa.
- Datas: armazenar em UTC; exibição segue o fuso parametrizado (padrão `America/Sao_Paulo`) via `parameter_service`.
- SLAs por severidade vêm de `SystemParameters` (defaults em `config.py`: 7/15/30/60 dias).

### Segredos
- Credenciais de integrações e `bind_password` LDAP **sempre** criptografadas com `safe_encrypt_secret` / `safe_decrypt_secret` (`crypto_utils.py`). Nunca retorne segredos em texto claro nas respostas da API (mascare).

### Fila assíncrona e Scheduler
- Uploads CSV e syncs de API são enfileirados como `ImportJob` via `enqueue_csv_job` / `enqueue_api_sync_job` (`services/job_queue/worker.py`) e processados pelo worker iniciado no `lifespan`.
- O scheduler (`integrations/scheduler.py`) verifica syncs agendados a cada 60 s.
- Operações demoradas **não** devem bloquear requisições HTTP — use a fila.

### Integrações de scanner
- Novo conector: criar `services/integrations/<nome>_client.py`, integrá‑lo em `sync_engine.py`, normalizar a saída para o mesmo modelo de Scan/Host/Vulnerability usado pelo parser Nessus, adicionar o tipo em `ScannerIntegration`, expor em `routes_integrations.py` e testar com mocks (sem chamadas de rede reais).

---

## 7. Convenções de Frontend

- SPA única em `index.html`; navegação/estado em `app.js`; chamadas HTTP **sempre** via objeto `API` em `api.js` (injeta `Authorization: Bearer`, trata 401).
- Sem frameworks, sem npm/bundler. JavaScript ES moderno, compatível com navegadores atuais.
- **Cache busting:** ao editar `api.js`, `charts.js`, `app.js` ou CSS, incremente o parâmetro de versão nos `<script>`/`<link>` do `index.html` (ex.: `?v=20261007_v63` → `?v=AAAAMMDD_vNN`).
- **Tailwind:** classes novas só aparecem após recompilar:
  ```bash
  ./scripts/build_css.sh   # gera frontend/public/css/tailwind.min.css
  ```
  Nunca edite `tailwind.min.css` manualmente. Estilos customizados vão em `css/styles.css` ou `frontend/src/input.css`.
- Suporte a **dark mode** (`darkMode: 'class'`) é obrigatório em todo componente novo.
- Siga rigorosamente o [`DESIGN.md`](./DESIGN.md): paleta `petroleum` (primária `#0f766e`), cores de severidade (crítica `#dc2626`, alta `#ea580c`, média `#d97706`, baixa `#0284c7`, info `#10b981`), fontes *Plus Jakarta Sans* / *Inter* / *JetBrains Mono*.
- Ícones: Lucide (`data-lucide="..."` + `lucide.createIcons()` após renderizações dinâmicas).
- Gráficos: Chart.js via `charts.js`; destrua instâncias anteriores antes de recriar.
- Para tarefas de UI/UX, utilize a skill **impeccable** (`.agent/skills/impeccable/SKILL.md`) e respeite `.impeccable/config.json`.
- Escape conteúdo dinâmico vindo da API com `this.escapeHtml(...)` (já existe em `app.js`) antes de inserir via `innerHTML` (dados de scan são não confiáveis — risco de XSS).

---

## 8. Regras de Segurança e Dados

- **Nunca** versione: `.env`, `data/`, `*.db`, `*.sql`, `*.crt`, `*.key`, `*.pem`, binário `tailwindcss` (ver `.gitignore`).
- **Nunca** leia, exiba ou copie conteúdo de `data/uploads/` ou dumps `.sql` para fora do ambiente — contêm dados reais de vulnerabilidades corporativas.
- Não execute operações destrutivas no banco (`DROP`, `TRUNCATE`, `DELETE` sem `WHERE`, `docker volume rm gvulstand_postgres_data`) sem consentimento explícito do usuário.
- Não altere credenciais padrão, CORS ou `SECRET_KEY` sem solicitação.
- Valide uploads (extensão/tamanho; Nginx limita a 200 MB).

---

## 9. Checklist Antes de Concluir uma Tarefa

- [ ] Código segue os padrões acima e mensagens ao usuário estão em pt-BR.
- [ ] Modelos alterados → `schemas.py` + migração idempotente em `init_db()` atualizados.
- [ ] Rotas novas protegidas por RBAC e registradas em `main.py`.
- [ ] Testes adicionados/atualizados e `pytest` passando.
- [ ] Frontend: Tailwind recompilado (se houver classes novas), versão de cache incrementada, dark mode verificado.
- [ ] Trilha de auditoria preservada para mudanças de status.
- [ ] Nenhum segredo, dado de cliente ou arquivo gerado incluído no commit.
- [ ] `PRODUCT.md` / `DESIGN.md` / este `AGENTS.md` atualizados se a mudança alterar capacidades, design ou convenções.

---

## 10. Comandos Úteis

| Ação | Comando |
|---|---|
| Subir stack | `docker compose up -d --build` |
| Reiniciar app | `docker compose restart web` |
| Logs da app | `docker logs -f gvulstand_app` |
| Shell no Postgres | `docker exec -it gvulstand_pg psql -U gvuluser -d gvulstand` |
| Rodar testes | `docker exec -it gvulstand_app pytest -q /app/backend/tests` |
| Compilar CSS | `./scripts/build_css.sh` |
| Vendorizar assets | `python scripts/download_assets.py` |
| Migrar SQLite→Postgres | `python backend/migrate_to_postgres.py` |
| Health check | `curl -k https://localhost/api/health` |
