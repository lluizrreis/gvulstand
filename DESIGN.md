---
name: GvulStand
description: Orquestração e Correção de Vulnerabilidades com Governança ISO 27001 e PDCA
colors:
  primary: "#0f766e"
  primary-hover: "#0d655e"
  primary-light: "#14b8a6"
  primary-surface: "#f0fdfa"
  primary-border: "#ccfbf1"
  secondary: "#0284c7"
  secondary-hover: "#0369a1"
  secondary-surface: "#e0f2fe"
  bg-canvas: "#f8f9fa"
  bg-surface: "#ffffff"
  bg-card: "#ffffff"
  bg-card-hover: "#f8fafc"
  dark-bg-canvas: "#0b0f19"
  dark-bg-surface: "#101726"
  dark-bg-card: "#131b2e"
  dark-bg-card-hover: "#17233b"
  text-primary: "#0f172a"
  text-secondary: "#475569"
  text-muted: "#64748b"
  dark-text-primary: "#f8fafc"
  dark-text-secondary: "#94a3b8"
  dark-text-muted: "#64748b"
  border-default: "#e2e8f0"
  border-subtle: "#f1f5f9"
  dark-border-default: "#1e293b"
  sev-critical: "#dc2626"
  sev-critical-bg: "#fee2e2"
  sev-high: "#ea580c"
  sev-high-bg: "#ffedd5"
  sev-medium: "#d97706"
  sev-medium-bg: "#fef3c7"
  sev-low: "#0284c7"
  sev-low-bg: "#e0f2fe"
  sev-info: "#10b981"
  sev-info-bg: "#d1fae5"
  exploit-purple: "#7c3aed"
  exploit-bg: "#f3e8ff"
typography:
  display:
    fontFamily: "'Plus Jakarta Sans', 'Inter', system-ui, sans-serif"
    fontSize: "1.875rem"
    fontWeight: 800
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  headline:
    fontFamily: "'Plus Jakarta Sans', 'Inter', system-ui, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.01em"
  title:
    fontFamily: "'Plus Jakarta Sans', 'Inter', system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 600
    lineHeight: 1.4
    letterSpacing: "-0.01em"
  body:
    fontFamily: "'Plus Jakarta Sans', 'Inter', system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "'Plus Jakarta Sans', 'Inter', system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "0.05em"
  code:
    fontFamily: "'JetBrains Mono', monospace"
    fontSize: "0.8125rem"
    fontWeight: 500
    lineHeight: 1.4
    letterSpacing: "normal"
rounded:
  sm: "8px"
  md: "10px"
  lg: "12px"
  xl: "16px"
  full: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "#ffffff"
    rounded: "{rounded.sm}"
    padding: "8px 16px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
    textColor: "#ffffff"
    rounded: "{rounded.sm}"
    padding: "8px 16px"
  card-glass:
    backgroundColor: "{colors.bg-card}"
    rounded: "{rounded.lg}"
    padding: "20px 24px"
  badge-critical:
    backgroundColor: "{colors.sev-critical-bg}"
    textColor: "{colors.sev-critical}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
  badge-exploit:
    backgroundColor: "{colors.exploit-bg}"
    textColor: "{colors.exploit-purple}"
    rounded: "{rounded.sm}"
    padding: "2px 8px"
---

# Design System: GvulStand

## Overview

**Creative North Star: "Sentinela de Segurança Corporativa" (The Cyber Defense Watchtower)**

O GvulStand é arquitetado como um centro de comando operacional de segurança da informação, onde cada elemento de interface serve ao propósito de diagnosticar, priorizar e remediar riscos cibernéticos sem ambiguidades. A estética é limpa, sóbria e corporativa, fundamentada na solidez do Verde Petróleo (*Petroleum Teal*) sobre superfícies em ardósia técnica (*Obsidian Slate* e *Clean White*). Em vez de metáforas futuristas dispersivas, a interface inspira autoridade, rigor militar de controle e confiança institucional.

A densidade é deliberadamente calculada para analistas e líderes SecOps: informações críticas — endereços IP, identificadores CVE, scores CVSS e prazos de SLA — são dispostas com máxima escaneabilidade visual através de micro-labels em caixa alta, tipografia tabular monospaçada e tabelas refinadas. O design prioriza o aproveitamento horizontal do espaço (90%+ de largura útil), eliminando rolagens verticais supérfluas e garantindo que o ciclo PDCA de remediação seja executado com velocidade.

Anti-referências visuais formalmente rejeitadas incluem: interfaces estilo "hacker neon/cyberpunk" com gradientes fluorescentes, dashboards genéricos de templates com cards decorativos desprovidos de dados acionáveis, e layouts inflados com espaçamento desmedido que forçam rolagens contínuas para tarefas operacionais.

**Key Characteristics:**
- **Rigor Analítico e Alta Densidade:** Estruturação orientada a dados com diferenciação tipográfica imediata entre prosa analítica e identificadores técnicos.
- **Autoridade Cromática Contida:** Verde Petróleo como âncora de segurança, com paleta de severidade estritamente reservada para sinalização CVSS 3.1.
- **Profundidade Tonal e Camadas Restritas:** Cartões com contornos sutis de 1px e elevação reativa apenas sob demanda interativa (hover lift suave).
- **Consistência Dual (Dark/Light):** Experiência nativa de alto contraste calibrada tanto para monitoramento contínuo em salas de operações (Dark) quanto para auditorias e relatórios impressos (Light).

## Colors

A paleta combina a autoridade institucional do Verde Petróleo com a disciplina operacional do Slate corporativo e uma sinalização de alerta universalmente alinhada à norma CVSS 3.1.

### Primary
- **Deep Petroleum Teal** (`#0F766E` / dark: `#14B8A6`): Cor mestra da identidade GvulStand. Utilizada em botões primários de ação, seletores de navegação ativos, ícones de marca e estados confirmados de governança. No dark mode, ilumina-se sutilmente para `#14B8A6` e `#2DD4BF` para garantir legibilidade impecável sobre fundo escuro.

### Secondary
- **Cyber Ocean Blue** (`#0284C7` / dark: `#38BDF8`): Utilizada em métricas secundárias, telemetria de rede, conexões de scanners via API e severidade CVSS Baixa (*Low*).

### Neutral
- **Obsidian Dark Canvas** (`#0B0F19` / `#101726`): Fundo principal e barras laterais no modo escuro, conferindo atmosfera técnica e conforto visual prolongado.
- **Obsidian Dark Card** (`#131B2E` / hover: `#17233B`): Superfície de cartões no modo escuro, com contorno sutil de 1px (`rgba(255, 255, 255, 0.08)`).
- **Clean Corporate Light Canvas** (`#F8F9FA` / `#FFFFFF`): Fundo e cartões no modo claro corporativo, com bordas neutras em Slate 200 (`#E2E8F0`).
- **Slate Text Hierarchy** (`#0F172A` / `#475569` / `#64748B` em claro; `#F8FAFC` / `#94A3B8` em escuro): Escala de contraste rigorosa para títulos, texto de suporte e metadados secundários.

### Functional (CVSS 3.1 & Exploits)
- **Critical Red** (`#DC2626` / dark: `#EF4444`): Riscos críticos com pontuação CVSS 9.0–10.0. Utilizada em badges, alertas de SLA estourado e indicadores de risco iminente.
- **High Orange** (`#EA580C` / dark: `#F97316`): Severidade alta CVSS 7.0–8.9.
- **Medium Amber** (`#D97706` / dark: `#FBBF24`): Severidade média CVSS 4.0–6.9.
- **Low Sky** (`#0284C7` / dark: `#38BDF8`): Severidade baixa CVSS 0.1–3.9.
- **Info Emerald** (`#10B981` / dark: `#34D399`): Informativo CVSS 0.0, itens corrigidos (*Remediated*) e status saudáveis.
- **Exploit Purple** (`#7C3AED` / dark: `#C084FC`): Indicador especial de exploit público funcional ou malware ativo, com animação de pulso contida na borda.

### Named Rules
**The Strict CVSS Rule.** As cores de severidade (vermelho, laranja, amarelo, azul, verde) são reservadas exclusivamente para representação de risco técnico e status de vulnerabilidade. É terminantemente proibido utilizar o vermelho crítico para botões comuns de cancelamento ou elementos decorativos.
**The Signal-Over-Noise Rule.** Cores de alerta aparecem em menos de 15% da área visível de qualquer tela em repouso. O contraste cromático existe para guiar o olho do analista direto ao perigo real.
**The Exploit Pulse Rule.** Apenas vulnerabilidades comprovadamente exploráveis ou com malware conhecido recebem o acento roxo (`#7C3AED`) e o efeito pulsante de borda.

## Typography

**Display Font:** "Plus Jakarta Sans" (com fallbacks: 'Inter', system-ui, sans-serif)
**Body Font:** "Plus Jakarta Sans" (com fallbacks: 'Inter', system-ui, sans-serif)
**Label/Mono Font:** "JetBrains Mono" (com fallbacks: monospace)

**Character:** A tipografia conjuga a geometria moderna e humana da família *Plus Jakarta Sans* para comandos e leitura executiva com a precisão mecânica inegociável da *JetBrains Mono* para todos os identificadores técnicos e telemetria de rede.

### Hierarchy
- **Display** (800 / Extrabold, 1.875rem / 30px, line-height 1.2, letter-spacing -0.02em): Títulos macro, KPIs principais e cabeçalhos de visualização executiva.
- **Headline** (700 / Bold, 1.25rem / 20px, line-height 1.3, letter-spacing -0.01em): Nomes de módulos, títulos de modais e cabeçalhos de grupos de ativos.
- **Title** (600 / Semibold, 1rem / 16px, line-height 1.4, letter-spacing -0.01em): Títulos de cartões, seções de formulários e nomes de planos de ação.
- **Body** (400 / Normal, 0.875rem / 14px, line-height 1.5): Textos explicativos, sinopses de vulnerabilidades e notas de auditoria.
- **Label / Overline** (600 / Semibold, 0.70rem–0.75rem, letter-spacing 0.06em, text-transform uppercase): Cabeçalhos de tabelas, tags de filtros, categorias de navegação e metadados de status.
- **Technical Code** (500 / Medium, 0.8125rem / 13px, monospace): Endereços IP, portas TCP/UDP, CVEs (ex: `CVE-2024-21626`), hashes e IDs de plugins Tenable/Nessus.

### Named Rules
**The Tabular Rigor Rule.** Qualquer dado numérico comparativo, endereço IP, hash ou timestamp deve ser renderizado com alinhamento tabular ou na fonte monoespaciada *JetBrains Mono* para evitar saltos visuais durante a triagem.

## Layout

O modelo espacial do GvulStand prioriza a máxima amplitude e densidade analítica:
- **Área Útil Otimizada:** O container principal consome aproximadamente 98% da largura disponível da viewport (`#app-view main`), permitindo visualização simultânea de tabelas complexas de vulnerabilidades sem quebra excessiva de colunas.
- **Navegação Vertical Esquerda:** Menu lateral persistente e esbelto (aproximadamente 260px) com iconografia Lucide em caixas dedicadas e badges numéricos reativos (ex: contador de jobs ativos).
- **Barra de Controle Superior:** Cabeçalho persistente contendo informações do usuário autenticado, alternador instantâneo de tema (Claro/Escuro), seletor de fuso horário e botão de logout.
- **Grid Modular:** Disposição em 12 colunas para dashboards executivos, com transição responsiva para 1 ou 2 colunas em telas reduzidas (breakpoints: sm: 640px, md: 768px, lg: 1024px, xl: 1280px).

## Elevation & Depth

O sistema adota a filosofia **Layered & Restrained** (camadas estruturadas e contidas). As superfícies em repouso repousam sobre um plano estável com contornos sutis de 1px (*hairline borders*), sem sombras pesadas. A tridimensionalidade e as sombras aparecem prioritariamente como resposta reativa a ações de foco e hover.

### Shadow Vocabulary
- **Card Rest Light** (`0 1px 3px 0 rgba(15, 23, 42, 0.05), 0 8px 24px -12px rgba(15, 23, 42, 0.08)`): Sombreamento ambiente leve que separa cartões brancos do fundo cinza claro.
- **Card Rest Dark** (`0 4px 20px -4px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(255, 255, 255, 0.04)`): Profundidade atmosférica em fundo escuro com borda sutil de contraste.
- **Card Hover Elevation** (`0 4px 6px -1px rgba(15, 118, 110, 0.06), 0 14px 28px -10px rgba(15, 23, 42, 0.12)` em claro; `0 10px 30px -5px rgba(0, 0, 0, 0.6), 0 0 15px rgba(20, 184, 166, 0.12)` em escuro): Reação ao mouse acompanhada de elevação tátil discreta (`transform: translateY(-2px)`).
- **Modal Depth** (`0 20px 25px -5px rgba(15, 23, 42, 0.1)` com `backdrop-filter: blur(8px)`): Foco total na janela sobreposta, isolando o contexto analítico inferior.

### Named Rules
**The Restrained Elevation Rule.** Sombras nunca são puramente decorativas. A elevação reforça hierarquia de janelas modais ou indica capacidade de clique imediato em cartões operacionais.

## Shapes

- **Geometria dos Cantos:**
  - Botões, Badges e Inputs: cantos arredondados contidos (8px / `radius-sm`).
  - Cartões Operacionais e Painéis de Métricas: cantos intermediários (12px / `radius-lg`).
  - Janelas Modais e Diálogos de Auditoria: cantos destacados (16px / `radius-xl`).
  - Indicadores Circulares e Avatares: cantos esféricos completos (`9999px` / `rounded-full`).
- **Contornos (Borders):** Traço de 1px contínuo em todas as fronteiras de cartões e tabelas, garantindo delimitação nítida mesmo sob variações de brilho em monitores de alta resolução.

## Components

### Buttons
- **Shape:** Arredondado suave (8px).
- **Primary:** Fundo Verde Petróleo (`#0F766E`), texto branco, borda sólida de 1px (`#0D655E`), padding `8px 16px` (ou `6px 12px` em botões compactos de tabela).
- **Hover / Focus:** Transição suave (200ms) para tom mais escuro (`#0D655E`) em tema claro ou tom brilhante (`#14B8A6`) em tema escuro, com sombra de realce teal.
- **Secondary / Ghost:** Fundo transparente, borda Slate 200/700, texto neutro, com preenchimento sutil ao hover.

### Badges de Severidade & Status
- **Shape:** Raio de 8px, padding compacto `2px 8px`, tipografia em peso 600–700 com texto em tamanho reduzido (11px–12px).
- **Variantes CVSS:** Cores de fundo suaves translúcidas combinadas a bordas contrastantes e texto saturado de alta legibilidade (`.badge-critical`, `.badge-high`, etc.).
- **Exploit Badge:** Fundo roxo suave (`#F3E8FF`), texto roxo escuro (`#5B21B6`), com borda animada em pulso cíclico de 2 segundos.

### Cards / Containers (.glass-panel)
- **Corner Style:** Raio de 12px (`var(--radius-lg)`).
- **Background:** `#FFFFFF` em tema claro; `#131B2E` em tema escuro.
- **Border:** 1px sólido `#E2E8F0` em claro; 1px translúcido `rgba(255, 255, 255, 0.08)` em escuro.
- **Hover Lift:** Elevação física com `transform: translateY(-2px)` e realce sutil na borda para cartões navegáveis (`.glass-panel-hover`).

### Tables (.gvul-table)
- **Style:** Linhas limpas corporativas com cabeçalhos em caixa alta (0.7rem, tracking 0.06em, peso 600).
- **Borders & Hover:** Divisores inferiores sutis de 1px entre linhas, com realce cromático instantâneo na linha sob o cursor (`tbody tr:hover`).
- **Variante Compacta:** `.gvul-table-compact` para visualização em alta densidade com padding reduzido (`0.45rem 0.75rem`) e tipografia 12px.

### Navigation Links (.sidebar-link)
- **Shape:** Raio de 10px, padding vertical `6px 12px`.
- **Active State:** Fundo suave em Verde Petróleo (`#E6F4F1` em claro, `rgba(20, 184, 166, 0.16)` em escuro), ícone em caixa destacada com fundo `#CCFBF1` e texto em peso 700.

## Do's and Don'ts

### Do:
- **Do** manter a largura útil expandida (98% da tela) para tabelas e comparativos de vulnerabilidades.
- **Do** utilizar *JetBrains Mono* obrigatoriamente para endereços IP, portas de rede, identificadores CVE e códigos de plugins.
- **Do** aplicar o Verde Petróleo (`#0F766E` / `#14B8A6`) como foco principal de ação e confirmação institucional.
- **Do** reservar as cores funcionais de severidade (vermelho, laranja, amarelo) com exclusividade para métricas de risco CVSS.
- **Do** preservar a trilha de auditoria e justificativas visíveis para qualquer status de governança ISO 27001.

### Don't:
- **Don't** utilizar estilos "hacker neon/cyberpunk", brilhos excessivos ou paletas com saturação desconexa da autoridade corporativa.
- **Don't** inflar espaçamentos verticais em tabelas e listas que prejudiquem a densidade necessária para triagem de SecOps.
- **Don't** utilizar cores críticas (vermelho CVSS) em botões comuns de fechar modal ou ações secundárias.
- **Don't** remover ou ocultar o código de identificação do plugin ou CVE nas listagens de vulnerabilidades.
- **Don't** permitir que elementos em repouso usem sombras volumosas que poluam a leitura de dados.
