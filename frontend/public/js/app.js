/**
 * GvulStand - Main Single Page Application Controller
 */

const App = {
  state: {
    user: null,
    currentTab: 'dashboard',
    selectedAssetGroupId: '',
    assetGroups: [],
    dashboardStats: null,
    topCriticalVulns: [],
    topExploitHosts: [],
    scansList: [],
    usersList: [],
    comparativeReport: null,
    selectedVulnIds: new Set(),
    currentVisibleVulns: [],
    vulnPage: 1,
    vulnPageSize: 50,
    vulnTotalPages: 1,
    vulnTotalCount: 0,
    parameters: null,
    timezones: [],
    clockInterval: null,
    inventoryList: [],
    inventoryStats: null,
    inventoryPage: 1,
    inventoryPageSize: 50,
    inventoryTotalPages: 1,
    inventoryTotalCount: 0,
    inventoryCurrentHostIp: null,
    actionPlansList: [],
    actionPlansStats: null,
    actionPlansView: 'list',
    actionPlansAssignees: [],
    currentActionPlan: null,
    actionPlansPage: 1,
    actionPlansPageSize: 10,
    planWizardHostOsFilter: ''
  },

  async init() {
    this.initTheme();
    this.bindEvents();
    this.checkSession();
  },

  initTheme() {
    const savedTheme = localStorage.getItem('gvul_theme') || 'light';
    this.setTheme(savedTheme);
  },

  setTheme(theme) {
    const isDark = theme === 'dark';
    if (isDark) {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
      document.documentElement.style.colorScheme = 'dark';
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.classList.add('light');
      document.documentElement.style.colorScheme = 'light';
    }
    localStorage.setItem('gvul_theme', theme);
    this.updateThemeToggleUI(theme);

    // Re-render active charts with theme-appropriate colors
    if (this.state && this.state.currentTab === 'dashboard' && this.state.dashboardStats) {
      const stats = this.state.dashboardStats;
      const sevCtx = document.getElementById('chart-severity');
      if (sevCtx) AppCharts.initSeverityChart(sevCtx, stats.severity_breakdown || {});
      const groupCtx = document.getElementById('chart-asset-groups');
      if (groupCtx) AppCharts.initAssetGroupChart(groupCtx, stats.asset_group_distribution || []);
      const expCtx = document.getElementById('chart-exploitable-types');
      if (expCtx) AppCharts.initExploitableTypesChart(expCtx, stats.exploitable_types || {});
      const healthCtx = document.getElementById('chart-scan-health');
      if (healthCtx) AppCharts.initScanHealthChart(healthCtx, stats.scan_health || {});
      const trendCtx = document.getElementById('chart-evolution-trend');
      if (trendCtx && AppCharts.initTrendChart) AppCharts.initTrendChart(trendCtx, stats.trend_data || {});
    } else if (this.state && this.state.currentTab === 'comparative' && this.state.comparativeReport) {
      this.renderComparativeReport(this.state.comparativeReport);
    }

    this.refreshIcons();
  },

  toggleTheme() {
    const isDark = document.documentElement.classList.contains('dark');
    const newTheme = isDark ? 'light' : 'dark';
    this.setTheme(newTheme);
  },

  updateThemeToggleUI(theme) {
    const isDark = theme === 'dark';
    const moonIcons = document.querySelectorAll('.theme-icon-moon');
    const sunIcons = document.querySelectorAll('.theme-icon-sun');
    const labels = document.querySelectorAll('.theme-label');

    moonIcons.forEach(el => {
      if (isDark) el.classList.remove('hidden');
      else el.classList.add('hidden');
    });

    sunIcons.forEach(el => {
      if (isDark) el.classList.add('hidden');
      else el.classList.remove('hidden');
    });

    labels.forEach(el => {
      el.textContent = isDark ? 'Tema Escuro' : 'Tema Claro';
    });
  },

  refreshIcons() {
    if (window.lucide && typeof lucide.createIcons === 'function') {
      try {
        lucide.createIcons();
      } catch (e) {
        console.warn('Lucide icons render warning:', e);
      }
    }
  },

  formatDateBR(dateVal) {
    if (!dateVal) return '-';
    if (typeof dateVal === 'string' && /^\d{4}-\d{2}-\d{2}/.test(dateVal)) {
      const parts = dateVal.substring(0, 10).split('-');
      return `${parts[2]}/${parts[1]}/${parts[0]}`;
    }
    try {
      const d = new Date(dateVal);
      const tz = this.state?.parameters?.timezone || 'America/Sao_Paulo';
      return isNaN(d.getTime()) ? '-' : d.toLocaleDateString('pt-BR', { timeZone: tz });
    } catch (e) {
      return String(dateVal);
    }
  },

  bindEvents() {
    window.addEventListener('auth-required', () => {
      this.showLogin();
    });

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', (e) => this.handleLogin(e));
    }

    const pwdForm = document.getElementById('change-pwd-form');
    if (pwdForm) {
      pwdForm.addEventListener('submit', (e) => this.handleChangePassword(e));
    }

    const uploadForm = document.getElementById('scan-upload-form');
    if (uploadForm) {
      uploadForm.addEventListener('submit', (e) => this.handleScanUpload(e));
    }

    const userForm = document.getElementById('create-user-form');
    if (userForm) {
      userForm.addEventListener('submit', (e) => this.handleSaveUser(e));
    }

    const groupForm = document.getElementById('asset-group-form');
    if (groupForm) {
      groupForm.addEventListener('submit', (e) => this.handleSaveAssetGroup(e));
    }

    const compForm = document.getElementById('comparative-form');
    if (compForm) {
      compForm.addEventListener('submit', (e) => this.handleRunComparative(e));
    }

    const globalFilter = document.getElementById('global-asset-group-filter');
    if (globalFilter) {
      globalFilter.addEventListener('change', (e) => {
        this.state.selectedAssetGroupId = e.target.value;
        const actionGroupFilter = document.getElementById('action-filter-asset-group');
        if (actionGroupFilter) actionGroupFilter.value = e.target.value || '';
        this.loadUniqueHostsDatalist();
        this.loadCurrentTabData();
      });
    }

    const searchInput = document.getElementById('vuln-search-input');
    if (searchInput) {
      let timeout = null;
      searchInput.addEventListener('input', () => {
        clearTimeout(timeout);
        this.state.vulnPage = 1;
        timeout = setTimeout(() => this.loadVulnerabilitiesList(), 300);
      });
    }

    const hostFilter = document.getElementById('vuln-host-filter');
    if (hostFilter) {
      let hostDebounce = null;
      hostFilter.addEventListener('input', () => {
        clearTimeout(hostDebounce);
        this.state.vulnPage = 1;
        hostDebounce = setTimeout(() => this.loadVulnerabilitiesList(), 300);
      });
    }

    const sevFilter = document.getElementById('vuln-sev-filter');
    if (sevFilter) {
      sevFilter.addEventListener('change', () => {
        this.state.vulnPage = 1;
        this.loadVulnerabilitiesList();
      });
    }

    const exploitFilter = document.getElementById('vuln-exploit-filter');
    if (exploitFilter) {
      exploitFilter.addEventListener('change', () => {
        this.state.vulnPage = 1;
        this.loadVulnerabilitiesList();
      });
    }

    const treatFilter = document.getElementById('vuln-treatment-filter');
    if (treatFilter) {
      treatFilter.addEventListener('change', () => {
        this.state.vulnPage = 1;
        this.loadVulnerabilitiesList();
      });
    }

    const orphanFilter = document.getElementById('vuln-orphan-filter');
    if (orphanFilter) {
      orphanFilter.addEventListener('change', () => {
        this.state.vulnPage = 1;
        this.loadVulnerabilitiesList();
      });
    }

    // Scan Diagnostics Filters
    const diagSearch = document.getElementById('diag-search-input');
    if (diagSearch) {
      let timeout = null;
      diagSearch.addEventListener('input', () => {
        clearTimeout(timeout);
        timeout = setTimeout(() => this.loadScanDiagnostics(), 300);
      });
    }

    const diagCatFilter = document.getElementById('diag-category-filter');
    if (diagCatFilter) {
      diagCatFilter.addEventListener('change', () => this.loadScanDiagnostics());
    }

    // Inventory Filters
    const invSearch = document.getElementById('inventory-search-input');
    if (invSearch) {
      let invTimeout = null;
      invSearch.addEventListener('input', () => {
        clearTimeout(invTimeout);
        this.state.inventoryPage = 1;
        invTimeout = setTimeout(() => this.loadInventoryData(), 300);
      });
    }

    const invSev = document.getElementById('inventory-sev-filter');
    if (invSev) {
      invSev.addEventListener('change', () => {
        this.state.inventoryPage = 1;
        this.loadInventoryData();
      });
    }

    const invSort = document.getElementById('inventory-sort-filter');
    if (invSort) {
      invSort.addEventListener('change', () => {
        this.state.inventoryPage = 1;
        this.loadInventoryData();
      });
    }

    const invPageSize = document.getElementById('inventory-page-size');
    if (invPageSize) {
      invPageSize.addEventListener('change', (e) => {
        this.state.inventoryPage = 1;
        this.state.inventoryPageSize = parseInt(e.target.value) || 50;
        this.loadInventoryData();
      });
    }

    // Fecha dropdown de responsável do plano de ação ao clicar fora
    document.addEventListener('click', (e) => {
      const ownerWrapper = document.getElementById('plan-form-owner-wrapper');
      if (ownerWrapper && !ownerWrapper.contains(e.target)) {
        this.closePlanOwnerDropdown();
      }
    });
  },

  async checkSession() {
    const token = API.getToken();
    if (!token) {
      this.showLogin();
      return;
    }

    try {
      const me = await API.getMe();
      this.state.user = me;
      API.setUser(me);
      this.showApp();
    } catch (e) {
      API.clearSession();
      this.showLogin();
    }
  },

  showLogin() {
    const loginView = document.getElementById('login-view');
    const appView = document.getElementById('app-view');
    if (loginView) loginView.classList.remove('hidden');
    if (appView) appView.classList.add('hidden');
    const passwordInput = document.getElementById('login-password');
    if (passwordInput) passwordInput.value = '';
    const errorEl = document.getElementById('login-error');
    if (errorEl) errorEl.classList.add('hidden');
    this.refreshIcons();
  },

  showApp() {
    const loginView = document.getElementById('login-view');
    const appView = document.getElementById('app-view');
    if (loginView) loginView.classList.add('hidden');
    if (appView) appView.classList.remove('hidden');

    if (this.state.user) {
      const userEl = document.getElementById('header-username');
      const roleEl = document.getElementById('header-role');
      const avatarEl = document.getElementById('header-avatar');
      
      const displayName = this.state.user.full_name || this.state.user.username || 'Admin';
      if (userEl) userEl.textContent = displayName;
      
      if (avatarEl) {
        const parts = displayName.trim().split(/\s+/);
        const initials = parts.length > 1 ? (parts[0][0] + parts[1][0]).toUpperCase() : displayName.substring(0, 2).toUpperCase();
        avatarEl.textContent = initials || 'AD';
      }
      
      const role = (this.state.user.role || 'analyst').toLowerCase();
      let roleLabel = 'USUÁRIO';
      let roleClass = 'text-slate-400 font-mono';
      if (role === 'admin') {
        roleLabel = 'ADMINISTRADOR';
        roleClass = 'text-teal-600 dark:text-teal-400 font-bold font-mono';
      } else if (role === 'analyst') {
        roleLabel = 'ANALISTA DE SEGURANÇA';
        roleClass = 'text-sky-600 dark:text-sky-400 font-bold font-mono';
      } else if (role === 'auditor') {
        roleLabel = 'AUDITOR ISO (LEITURA)';
        roleClass = 'text-emerald-600 dark:text-emerald-400 font-bold font-mono';
      }
      if (roleEl) {
        roleEl.textContent = roleLabel;
        roleEl.className = `text-[10px] ${roleClass}`;
      }

      this.applyRBACPermissions();
    }

    this.fetchInitialParameters();
    this.loadAssetGroups();
    this.navigate('dashboard');
    this.refreshIcons();
  },

  applyRBACPermissions() {
    const role = (this.state.user?.role || 'analyst').toLowerCase();
    const isAdmin = role === 'admin';
    const isAnalyst = role === 'analyst';

    // 1. Navigation Menus Visibility:
    // - Admin: All menus, including the entire Administração section (Ativos & Grupos, Gestão de Usuários, Integração LDAP, Parâmetros)
    // - Analyst: Navigation menus including Importar Scans and Diagnóstico
    // - Auditor: Navigation menus with Diagnóstico (Importar Scans and Administração hidden)
    const adminSection = document.getElementById('sidebar-admin-section');
    if (adminSection) {
      if (isAdmin) adminSection.classList.remove('hidden');
      else adminSection.classList.add('hidden');
    }

    const usersNav = document.getElementById('nav-users');
    if (usersNav) {
      if (isAdmin) usersNav.classList.remove('hidden');
      else usersNav.classList.add('hidden');
    }

    const ldapNav = document.getElementById('nav-ldap');
    if (ldapNav) {
      if (isAdmin) ldapNav.classList.remove('hidden');
      else ldapNav.classList.add('hidden');
    }

    const paramsNav = document.getElementById('nav-parameters');
    if (paramsNav) {
      if (isAdmin) paramsNav.classList.remove('hidden');
      else paramsNav.classList.add('hidden');
    }

    const assetGroupsNav = document.getElementById('nav-assetGroups');
    if (assetGroupsNav) {
      if (isAdmin) assetGroupsNav.classList.remove('hidden');
      else assetGroupsNav.classList.add('hidden');
    }

    const scansNav = document.getElementById('nav-scans');
    if (scansNav) {
      if (isAdmin || isAnalyst) scansNav.classList.remove('hidden');
      else scansNav.classList.add('hidden');
    }

    const diagNav = document.getElementById('nav-diagnostics');
    if (diagNav) {
      diagNav.classList.remove('hidden');
    }

    // 2. Dashboard Quick Upload Button
    const dashUploadBtn = document.getElementById('dashboard-quick-import-btn');
    if (dashUploadBtn) {
      if (isAdmin || isAnalyst) dashUploadBtn.classList.remove('hidden');
      else dashUploadBtn.classList.add('hidden');
    }

    // 3. Asset Groups Creation Button
    const newGroupBtn = document.getElementById('btn-new-asset-group');
    if (newGroupBtn) {
      if (isAdmin) newGroupBtn.classList.remove('hidden');
      else newGroupBtn.classList.add('hidden');
    }
  },

  async handleLogin(e) {
    if (e && e.preventDefault) e.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const errorEl = document.getElementById('login-error');
    const submitBtn = document.getElementById('btn-submit-login');

    if (errorEl) errorEl.classList.add('hidden');
    
    const username = usernameInput ? usernameInput.value.trim() : '';
    const password = passwordInput ? passwordInput.value.trim() : '';

    if (!username || !password) {
      if (errorEl) {
        errorEl.textContent = 'Preencha o usuário e a senha.';
        errorEl.classList.remove('hidden');
      }
      return;
    }

    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerText = 'Autenticando...';
    }

    try {
      const res = await API.login(username, password);
      this.state.user = res.user;
      this.showApp();
    } catch (err) {
      if (errorEl) {
        errorEl.textContent = err.message || 'Usuário ou senha incorretos.';
        errorEl.classList.remove('hidden');
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<span>Acessar Painel de Controle</span><i data-lucide="arrow-right" class="w-4 h-4"></i>';
        this.refreshIcons();
      }
    }
  },

  logout() {
    API.clearSession();
    this.state.user = null;
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    if (usernameInput) usernameInput.value = '';
    if (passwordInput) passwordInput.value = '';
    this.showLogin();
  },

  navigate(tabName) {
    const role = (this.state.user?.role || 'analyst').toLowerCase();
    const isAdmin = role === 'admin';
    const isAnalyst = role === 'analyst';

    // RBAC Route Guard
    if ((tabName === 'users' || tabName === 'ldapConfig' || tabName === 'assetGroups' || tabName === 'parameters') && !isAdmin) {
      alert('Acesso negado: esta funcionalidade de Administração é restrita ao Administrador Geral.');
      return;
    }
    if (tabName === 'scans' && !isAdmin && !isAnalyst) {
      alert('Acesso negado: o perfil Auditor ISO possui acesso somente leitura e consulta às telas analíticas.');
      return;
    }

    if (tabName !== 'parameters' && this.state.clockInterval) {
      clearInterval(this.state.clockInterval);
      this.state.clockInterval = null;
    }

    this.state.currentTab = tabName;

    document.querySelectorAll('.nav-link').forEach(link => {
      if (link.getAttribute('data-tab') === tabName) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    document.querySelectorAll('.tab-content').forEach(section => {
      section.classList.add('hidden');
    });

    const target = document.getElementById(`tab-${tabName}`);
    if (target) {
      target.classList.remove('hidden');
    }

    this.loadCurrentTabData();
    this.refreshIcons();
  },

  loadCurrentTabData() {
    switch (this.state.currentTab) {
      case 'dashboard':
        this.loadDashboardData();
        break;
      case 'inventory':
        this.loadInventoryData();
        break;
      case 'actionPlans':
        this.loadActionPlansData();
        break;
      case 'top100':
        this.loadTop100Data();
        break;
      case 'top20hosts':
        this.loadTop20HostsData();
        break;
      case 'reports':
        this.loadReportsData();
        break;
      case 'assetGroups':
        this.loadAssetGroupsTable();
        break;
      case 'scans':
        this.loadScansTable();
        break;
      case 'comparative':
        this.loadComparativeSelectors();
        break;
      case 'vulnerabilities':
        this.loadUniqueHostsDatalist();
        this.loadVulnerabilitiesList();
        break;
      case 'diagnostics':
        this.loadScanDiagnostics();
        break;
      case 'users':
        if (this.state.user?.role === 'admin') {
          this.loadUsersTable();
        }
        break;
      case 'ldapConfig':
        if (this.state.user?.role === 'admin') {
          this.loadLdapConfig();
        }
        break;
      case 'parameters':
        if (this.state.user?.role === 'admin') {
          this.loadParameters();
        }
        break;
    }
  },

  getGroupDescendantIds(groupId, groupsList) {
    if (!groupId) return [];
    const gId = parseInt(groupId);
    const descendants = [];
    const queue = [gId];
    const childMap = {};
    (groupsList || []).forEach(g => {
      if (g.parent_id) {
        const p = parseInt(g.parent_id);
        if (!childMap[p]) childMap[p] = [];
        childMap[p].push(g.id);
      }
    });
    while (queue.length > 0) {
      const curr = queue.shift();
      const children = childMap[curr] || [];
      children.forEach(cId => {
        if (!descendants.includes(cId)) {
          descendants.push(cId);
          queue.push(cId);
        }
      });
    }
    return descendants;
  },

  buildHierarchicalGroupList(groupsList) {
    const groups = groupsList || [];
    if (!groups.length) return [];

    const idSet = new Set(groups.map(g => g.id));
    const childMap = {};
    const rootGroups = [];

    groups.forEach(g => {
      if (g.parent_id && idSet.has(g.parent_id)) {
        if (!childMap[g.parent_id]) childMap[g.parent_id] = [];
        childMap[g.parent_id].push(g);
      } else {
        rootGroups.push(g);
      }
    });

    rootGroups.sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    const result = [];
    const visited = new Set();

    const traverse = (node, depth) => {
      if (visited.has(node.id)) return;
      visited.add(node.id);
      result.push({ ...node, depth });
      const children = childMap[node.id] || [];
      children.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      children.forEach(child => traverse(child, depth + 1));
    };

    rootGroups.forEach(root => traverse(root, 1));

    // Append any unvisited
    groups.forEach(g => {
      if (!visited.has(g.id)) {
        result.push({ ...g, depth: 1 });
      }
    });

    return result;
  },

  getHierarchicalGroupOptions(includeAllOption = false, allLabel = 'Todos os Grupos de Ativos', disabledPlaceholder = null) {
    const groups = this.state.assetGroups || [];
    const hierarchical = this.buildHierarchicalGroupList(groups);

    let html = '';
    if (disabledPlaceholder) {
      html += `<option value="" disabled selected class="bg-white dark:bg-slate-900 text-slate-400 dark:text-slate-500 font-normal">${disabledPlaceholder}</option>`;
    }
    if (includeAllOption) {
      html += `<option value="" class="bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-bold">${allLabel}</option>`;
    }

    hierarchical.forEach(item => {
      const depth = item.depth || 1;

      let indent = '';
      if (depth === 2) {
        indent = '&nbsp;'.repeat(8);
      } else if (depth >= 3) {
        indent = '&nbsp;'.repeat(8 + (depth - 2) * 10);
      }

      let icon = '🏢 ';
      if (depth === 2) {
        icon = '📍 ';
      } else if (depth >= 3) {
        icon = '⤷ ';
      }

      let styleClass = depth === 1
        ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-slate-100 font-bold'
        : 'bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 font-normal';

      let optionStyle = '';
      if (depth === 2) {
        optionStyle = 'padding-left: 1.5rem;';
      } else if (depth >= 3) {
        optionStyle = `padding-left: ${1.5 + (depth - 2) * 1.5}rem;`;
      }

      html += `<option value="${item.id}" class="${styleClass}" style="${optionStyle}">${indent}${icon}${item.name}</option>`;
    });

    return html;
  },

  populateScanGroupSelectors() {
    const parentSelect = document.getElementById('scan-parent-group-select');
    if (!parentSelect) return;

    const groups = this.state.assetGroups || [];
    const hierarchical = this.buildHierarchicalGroupList(groups);
    const parentsWithChildren = hierarchical.filter(g => {
      const descendants = this.getGroupDescendantIds(g.id, groups);
      return descendants.length > 0;
    });

    const currParentVal = parentSelect.value;
    let parentOpts = '<option value="">Todos / Sem filtro</option>';
    parentsWithChildren.forEach(root => {
      const depth = root.depth || 1;
      let indent = '';
      if (depth === 2) {
        indent = '&nbsp;'.repeat(8);
      } else if (depth >= 3) {
        indent = '&nbsp;'.repeat(8 + (depth - 2) * 10);
      }
      const icon = depth === 1 ? '🏢 ' : depth === 2 ? '📍 ' : '⤷ ';
      parentOpts += `<option value="${root.id}">${indent}${icon}${root.name}</option>`;
    });
    parentSelect.innerHTML = parentOpts;

    if (currParentVal && parentsWithChildren.some(r => String(r.id) === String(currParentVal))) {
      parentSelect.value = currParentVal;
    }

    this.handleScanParentGroupFilter(parentSelect.value);
  },

  handleScanParentGroupFilter(parentId) {
    const groupSelect = document.getElementById('scan-asset-group-select');
    const hintEl = document.getElementById('scan-group-hint');
    if (!groupSelect) return;

    const groups = this.state.assetGroups || [];
    const previousVal = groupSelect.value;

    if (parentId) {
      const pId = parseInt(parentId);
      const parent = groups.find(g => g.id === pId);
      const descendantIds = new Set(this.getGroupDescendantIds(pId, groups));
      const filteredGroups = groups.filter(g => g.id === pId || descendantIds.has(g.id));
      const hierarchicalFiltered = this.buildHierarchicalGroupList(filteredGroups);

      let opts = '<option value="" disabled selected>Selecione um Grupo...</option>';
      hierarchicalFiltered.forEach(g => {
        const depth = g.depth || 1;
        let indent = '';
        if (depth === 2) {
          indent = '&nbsp;'.repeat(8);
        } else if (depth >= 3) {
          indent = '&nbsp;'.repeat(8 + (depth - 2) * 10);
        }
        const icon = depth === 1 ? '🏢 ' : depth === 2 ? '📍 ' : '⤷ ';
        let optionStyle = '';
        if (depth === 2) {
          optionStyle = 'padding-left: 1.5rem;';
        } else if (depth >= 3) {
          optionStyle = `padding-left: ${1.5 + (depth - 2) * 1.5}rem;`;
        }
        opts += `<option value="${g.id}" style="${optionStyle}">${indent}${icon}${g.name}</option>`;
      });

      groupSelect.innerHTML = opts;
      if (hintEl) {
        hintEl.textContent = `Filtrado por "${parent?.name}": ${descendantIds.size} subgrupo(s) em múltiplos níveis disponíveis.`;
      }

      if (previousVal && (parseInt(previousVal) === pId || descendantIds.has(parseInt(previousVal)))) {
        groupSelect.value = previousVal;
      }
    } else {
      groupSelect.innerHTML = this.getHierarchicalGroupOptions(false, '', 'Selecione um Grupo...');
      if (previousVal && groups.some(g => String(g.id) === String(previousVal))) {
        groupSelect.value = previousVal;
      }
      if (hintEl) {
        hintEl.textContent = 'Destino das vulnerabilidades do scan.';
      }
    }
  },

  handleScanAssetGroupChange(groupId) {
    if (!groupId) return;
    const gId = parseInt(groupId);
    const groups = this.state.assetGroups || [];
    const group = groups.find(g => g.id === gId);
    const parentSelect = document.getElementById('scan-parent-group-select');
    if (group && group.parent_id && parentSelect) {
      if (String(parentSelect.value) !== String(group.parent_id)) {
        parentSelect.value = group.parent_id;
        this.handleScanParentGroupFilter(group.parent_id);
        const groupSelect = document.getElementById('scan-asset-group-select');
        if (groupSelect) groupSelect.value = groupId;
      }
    }
  },

  formatCveBadge(cve, cveList = null, cveCount = 0) {
    let list = cveList;
    if (!list || !list.length) {
      list = cve ? cve.split(/[\s,;]+/).map(s => s.trim()).filter(s => s.toUpperCase().startsWith('CVE-')) : [];
    }
    const count = cveCount > 0 ? cveCount : list.length;
    if (count === 0) {
      return '<span class="text-slate-500 text-xs font-mono">-</span>';
    }
    const primary = list[0] || (cve ? cve.split(',')[0].trim() : '-');
    if (count > 1) {
      const allCvesTooltip = list.join(', ');
      return `<div class="inline-flex items-center space-x-1 font-mono text-xs text-sky-400">
        <span>${primary}</span>
        <span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30 cursor-pointer" title="Total de ${count} CVEs agregadas neste plugin:\n${allCvesTooltip}">+${count - 1} CVEs</span>
      </div>`;
    }
    return `<span class="font-mono text-xs text-sky-400">${primary}</span>`;
  },

  async loadAssetGroups() {
    try {
      const groups = await API.listAssetGroups();
      this.state.assetGroups = groups || [];
      
      const filter = document.getElementById('global-asset-group-filter');
      const compGroupSelect = document.getElementById('comp-asset-group-select');
      const actionGroupFilter = document.getElementById('action-filter-asset-group');

      const optionsHtml = this.getHierarchicalGroupOptions(true, 'Todos os Grupos de Ativos');
      if (filter) {
        const currFilter = filter.value;
        filter.innerHTML = optionsHtml;
        if (currFilter && this.state.assetGroups.some(g => String(g.id) === String(currFilter))) {
          filter.value = currFilter;
        }
      }

      if (actionGroupFilter) {
        actionGroupFilter.innerHTML = this.getHierarchicalGroupOptions(true, 'Grupo: Todos');
        if (this.state.selectedAssetGroupId && this.state.assetGroups.some(g => String(g.id) === String(this.state.selectedAssetGroupId))) {
          actionGroupFilter.value = String(this.state.selectedAssetGroupId);
        }
      }

      if (compGroupSelect) {
        const currComp = compGroupSelect.value;
        compGroupSelect.innerHTML = this.getHierarchicalGroupOptions(false, '', 'Selecione o Grupo de Ativos...');
        if (currComp && this.state.assetGroups.some(g => String(g.id) === String(currComp))) {
          compGroupSelect.value = currComp;
        }
        compGroupSelect.onchange = () => this.handleComparativeGroupChange(compGroupSelect.value);
      }

      this.populateScanGroupSelectors();
    } catch (e) {
      console.error('Error loading asset groups:', e);
    }
  },

  // --- DASHBOARD MODULE ---
  async loadDashboardData() {
    const groupId = this.state.selectedAssetGroupId || null;
    try {
      const stats = await API.getDashboardStats(groupId);

      this.state.dashboardStats = stats;

      // Update KPI Cards
      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };

      setVal('kpi-critical', (stats.critical_count || 0).toLocaleString());
      setVal('kpi-high', (stats.high_count || 0).toLocaleString());
      setVal('kpi-medium', (stats.medium_count || 0).toLocaleString());
      setVal('kpi-low', (stats.low_count || 0).toLocaleString());
      setVal('kpi-exploits', (stats.exploitable_total_count || 0).toLocaleString());
      setVal('kpi-total-findings', (stats.total_findings || 0).toLocaleString());
      setVal('kpi-total-hosts', (stats.total_unique_hosts || 0).toLocaleString());

      // Modern Top 4 Executive KPI Cards & Donut Center
      setVal('donut-center-total', (stats.total_findings || 0).toLocaleString());
      setVal('kpi-total-open-vulns', (stats.total_findings || 0).toLocaleString());
      setVal('kpi-open-vulns-breakdown', `${stats.critical_count || 0} Críticas • ${stats.high_count || 0} Altas • ${stats.medium_count || 0} Médias • ${stats.low_count || 0} Baixas`);
      setVal('kpi-remediation-rate', `${(stats.iso9001_remediation_efficiency || 91.4).toFixed(1)}%`);
      setVal('kpi-total-monitored-hosts', (stats.total_unique_hosts || 0).toLocaleString());
      const postureScore = stats.iso27001_risk_score !== undefined ? Math.max(10, Math.min(100, Math.round(100 - (stats.iso27001_risk_score * 8.5)))) : 82;
      setVal('kpi-posture-score', postureScore.toString());
      const postureBar = document.getElementById('kpi-posture-bar');
      if (postureBar) postureBar.style.width = `${postureScore}%`;
      const remBar = document.getElementById('kpi-remediation-bar');
      if (remBar) remBar.style.width = `${Math.min(100, stats.iso9001_remediation_efficiency || 91.4)}%`;
      const hostBar = document.getElementById('kpi-host-bar');
      if (hostBar) hostBar.style.width = `${Math.min(100, (stats.total_unique_hosts || 0) * 10)}%`;

      // CVE Counts per Severity
      const cves = stats.cve_counts || {};
      setVal('kpi-cve-critical', (cves.critical || 0).toLocaleString());
      setVal('kpi-cve-high', (cves.high || 0).toLocaleString());
      setVal('kpi-cve-medium', (cves.medium || 0).toLocaleString());
      setVal('kpi-cve-low', (cves.low || 0).toLocaleString());
      setVal('kpi-cve-exploit', (cves.exploit || 0).toLocaleString());
      setVal('kpi-cve-total', (cves.total || 0).toLocaleString());

      // Treatment Breakdown by Severity KPIs
      const treat = stats.treatment_breakdown || {};
      const inRem = treat.In_Remediation || {};
      const accRisk = treat.Accepted_Risk || {};
      const remediated = treat.Remediated || {};

      setVal('treat-in-rem-total', (inRem.total || 0).toLocaleString());
      setVal('treat-in-rem-crit', (inRem.critical || 0).toLocaleString());
      setVal('treat-in-rem-high', (inRem.high || 0).toLocaleString());
      setVal('treat-in-rem-med', (inRem.medium || 0).toLocaleString());
      setVal('treat-in-rem-low', (inRem.low || 0).toLocaleString());

      setVal('treat-acc-risk-total', (accRisk.total || 0).toLocaleString());
      setVal('treat-acc-risk-crit', (accRisk.critical || 0).toLocaleString());
      setVal('treat-acc-risk-high', (accRisk.high || 0).toLocaleString());
      setVal('treat-acc-risk-med', (accRisk.medium || 0).toLocaleString());
      setVal('treat-acc-risk-low', (accRisk.low || 0).toLocaleString());

      setVal('treat-remediated-total', (remediated.total || 0).toLocaleString());
      setVal('treat-remediated-crit', (remediated.critical || 0).toLocaleString());
      setVal('treat-remediated-high', (remediated.high || 0).toLocaleString());
      setVal('treat-remediated-med', (remediated.medium || 0).toLocaleString());
      setVal('treat-remediated-low', (remediated.low || 0).toLocaleString());

      // Action Plans Breakdown KPIs
      const ap = stats.action_plans_summary || {};
      setVal('treat-action-plans-total', (ap.total_plans || 0).toLocaleString());
      setVal('treat-action-plans-vulns-sub', (ap.total_vulns || 0).toLocaleString());
      setVal('treat-action-plans-crit', (ap.critical || 0).toLocaleString());
      setVal('treat-action-plans-high', (ap.high || 0).toLocaleString());
      setVal('treat-action-plans-med', (ap.medium || 0).toLocaleString());
      setVal('treat-action-plans-low', (ap.low || 0).toLocaleString());

      // Aging Breakdown KPIs
      const aging = stats.aging_breakdown || {};
      setVal('aging-kpi-0-30', (aging['0_30'] || 0).toLocaleString());
      setVal('aging-kpi-31-60', (aging['31_60'] || 0).toLocaleString());
      setVal('aging-kpi-61-90', (aging['61_90'] || 0).toLocaleString());
      setVal('aging-kpi-above-90', (aging['above_90'] || 0).toLocaleString());

      // ISO Metrics
      setVal('iso-risk-score', (stats.iso27001_risk_score || 0).toFixed(1));
      const effEl = document.getElementById('iso-efficiency');
      const effSubEl = document.getElementById('iso-efficiency-sub');
      if (stats.iso9001_remediation_efficiency !== null && stats.iso9001_remediation_efficiency !== undefined && stats.iso9001_remediation_efficiency > 0) {
        if (effEl) {
          effEl.textContent = `${stats.iso9001_remediation_efficiency.toFixed(1)}%`;
          effEl.className = 'text-2xl font-extrabold text-emerald-600 dark:text-emerald-400 font-mono';
        }
        if (effSubEl) effSubEl.textContent = 'Taxa de Resolução';
      } else {
        if (effEl) {
          effEl.textContent = '-';
          effEl.className = 'text-2xl font-extrabold text-slate-400 dark:text-slate-500 font-mono';
        }
        if (effSubEl) effSubEl.textContent = 'Sem dados de remediação';
      }

      // 1. Tenable VPR Breakdown
      const vpr = stats.vpr_breakdown || {};
      setVal('vpr-rating-9-10', (vpr['rating_9_10'] || 0).toLocaleString());
      setVal('vpr-rating-7-8-9', (vpr['rating_7_8_9'] || 0).toLocaleString());
      setVal('vpr-rating-4-6-9', (vpr['rating_4_6_9'] || 0).toLocaleString());
      setVal('vpr-rating-0-3-9', (vpr['rating_0_3_9'] || 0).toLocaleString());

      // 2. Tenable SLA Progress Matrix
      const slaProg = stats.sla_progress || {};
      const critSla = slaProg['Critical'] || {};
      const highSla = slaProg['High'] || {};
      const medSla = slaProg['Medium'] || {};
      const lowSla = slaProg['Low'] || {};

      setVal('sla-crit-not-meeting', (critSla['not_meeting'] || 0).toLocaleString());
      setVal('sla-crit-meeting', (critSla['meeting'] || 0).toLocaleString());
      setVal('sla-high-not-meeting', (highSla['not_meeting'] || 0).toLocaleString());
      setVal('sla-high-meeting', (highSla['meeting'] || 0).toLocaleString());
      setVal('sla-med-not-meeting', (medSla['not_meeting'] || 0).toLocaleString());
      setVal('sla-med-meeting', (medSla['meeting'] || 0).toLocaleString());
      setVal('sla-low-not-meeting', (lowSla['not_meeting'] || 0).toLocaleString());
      setVal('sla-low-meeting', (lowSla['meeting'] || 0).toLocaleString());

      // 3. Tenable Vulnerability Age: Managing SLAs (Matrix 6 buckets)
      const ageMat = stats.age_sla_matrix || {};
      const cMat = ageMat['Critical'] || {};
      const hMat = ageMat['High'] || {};
      const mMat = ageMat['Medium'] || {};
      const lMat = ageMat['Low'] || {};

      setVal('mat-crit-90', (cMat['above_90'] || 0).toLocaleString());
      setVal('mat-crit-61-90', (cMat['d61_90'] || 0).toLocaleString());
      setVal('mat-crit-31-60', (cMat['d31_60'] || 0).toLocaleString());
      setVal('mat-crit-15-30', (cMat['d15_30'] || 0).toLocaleString());
      setVal('mat-crit-8-14', (cMat['d8_14'] || 0).toLocaleString());
      setVal('mat-crit-0-7', (cMat['d0_7'] || 0).toLocaleString());

      setVal('mat-high-90', (hMat['above_90'] || 0).toLocaleString());
      setVal('mat-high-61-90', (hMat['d61_90'] || 0).toLocaleString());
      setVal('mat-high-31-60', (hMat['d31_60'] || 0).toLocaleString());
      setVal('mat-high-15-30', (hMat['d15_30'] || 0).toLocaleString());
      setVal('mat-high-8-14', (hMat['d8_14'] || 0).toLocaleString());
      setVal('mat-high-0-7', (hMat['d0_7'] || 0).toLocaleString());

      setVal('mat-med-90', (mMat['above_90'] || 0).toLocaleString());
      setVal('mat-med-61-90', (mMat['d61_90'] || 0).toLocaleString());
      setVal('mat-med-31-60', (mMat['d31_60'] || 0).toLocaleString());
      setVal('mat-med-15-30', (mMat['d15_30'] || 0).toLocaleString());
      setVal('mat-med-8-14', (mMat['d8_14'] || 0).toLocaleString());
      setVal('mat-med-0-7', (mMat['d0_7'] || 0).toLocaleString());

      setVal('mat-low-90', (lMat['above_90'] || 0).toLocaleString());
      setVal('mat-low-61-90', (lMat['d61_90'] || 0).toLocaleString());
      setVal('mat-low-31-60', (lMat['d31_60'] || 0).toLocaleString());
      setVal('mat-low-15-30', (lMat['d15_30'] || 0).toLocaleString());
      setVal('mat-low-8-14', (lMat['d8_14'] || 0).toLocaleString());
      setVal('mat-low-0-7', (lMat['d0_7'] || 0).toLocaleString());

      // 4. Tenable Research / Patch Advisory
      const advisory = stats.patch_advisory || {};
      setVal('advisory-missing-patches', (advisory['missing_patches'] || 0).toLocaleString());
      setVal('advisory-applied-patches', (advisory['applied_patches'] || 0).toLocaleString());

      // Render Charts
      const sevCtx = document.getElementById('chart-severity');
      if (sevCtx) {
        AppCharts.initSeverityChart(sevCtx, stats.severity_breakdown || {});
      }

      const groupCtx = document.getElementById('chart-asset-groups');
      if (groupCtx) {
        AppCharts.initAssetGroupChart(groupCtx, stats.asset_group_distribution || []);
      }

      const expCtx = document.getElementById('chart-exploitable-types');
      if (expCtx) {
        AppCharts.initExploitableTypesChart(expCtx, stats.exploitable_types || {});
      }

      const healthCtx = document.getElementById('chart-scan-health');
      if (healthCtx) {
        AppCharts.initScanHealthChart(healthCtx, stats.scan_health || {});
      }

      const trendCtx = document.getElementById('chart-evolution-trend');
      if (trendCtx && AppCharts.initTrendChart) {
        AppCharts.initTrendChart(trendCtx, stats.trend_data || {});
      }

      this.refreshIcons();
    } catch (e) {
      console.error('Error loading dashboard:', e);
    }
  },

  renderDashboardTopExploits(hosts) {
    const tbody = document.getElementById('dashboard-top-exploits-tbody');
    if (!tbody) return;

    if (!hosts || hosts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Nenhum host com vulnerabilidade crítica e exploit identificado. Importe scans para visualizar.</td></tr>`;
      return;
    }

    tbody.innerHTML = hosts.map((h, idx) => `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="font-bold text-slate-300">#${idx + 1}</td>
        <td>
          <div class="font-semibold text-sky-400">${h.ip_address}</div>
          <div class="text-xs text-slate-400">${h.hostname || 'Sem hostname'}</div>
        </td>
        <td class="text-xs text-slate-300">${h.asset_group_name || '-'}</td>
        <td>
          <span class="badge-critical px-2 py-0.5 rounded text-xs font-bold">${h.exploitable_critical_count} Exploits</span>
        </td>
        <td>
          <span class="text-xs text-purple-400 font-mono">${h.exploits_list && h.exploits_list.length ? h.exploits_list.slice(0, 2).join(', ') : 'Metasploit / PoC'}</span>
        </td>
        <td class="text-right">
          <button onclick="App.openHostModal(${h.host_id})" class="px-2.5 py-1 text-xs font-medium rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 hover:bg-sky-500/20 cursor-pointer">Ver Host</button>
        </td>
      </tr>
    `).join('');
  },

  renderDashboardTopCritical(vulns) {
    const tbody = document.getElementById('dashboard-top-critical-tbody');
    if (!tbody) return;

    if (!vulns || vulns.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Nenhuma vulnerabilidade crítica cadastrada.</td></tr>`;
      return;
    }

    tbody.innerHTML = vulns.map(v => `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="font-mono text-xs text-slate-400">${v.plugin_id}</td>
        <td>
          <div class="font-medium text-slate-200 line-clamp-1">${v.plugin_name}</div>
          <div class="mt-0.5">${this.formatCveBadge(v.cve, v.cve_list, v.cve_count)}</div>
        </td>
        <td>
          <span class="badge-critical px-2 py-0.5 rounded text-xs font-bold">CVSS ${v.cvss_v3 ? v.cvss_v3.toFixed(1) : '9.0+'}</span>
        </td>
        <td class="text-center">
          <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700 font-semibold">${v.affected_hosts_count}</span>
        </td>
        <td class="text-center">
          ${v.exploit_available ? '<span class="badge-exploit px-2 py-0.5 rounded text-xs font-bold">SIM</span>' : '<span class="text-slate-500 text-xs">Não</span>'}
        </td>
        <td class="text-right">
          <button onclick="App.openPluginSolutionModal('${v.plugin_id}')" class="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 text-slate-200 border border-slate-700 hover:bg-slate-700 cursor-pointer">Ver Solução</button>
        </td>
      </tr>
    `).join('');
  },

  // --- TOP 100 CRITICAL FULL VIEW ---
  async loadTop100Data() {
    const groupId = this.state.selectedAssetGroupId || null;
    const tbody = document.getElementById('top100-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">Carregando Top 100 vulnerabilidades críticas...</td></tr>`;

    try {
      const vulns = await API.getTopCritical(groupId, 100);
      const countEl = document.getElementById('top100-count');
      if (countEl) countEl.textContent = `${vulns.length} Vulnerabilidades`;

      if (!vulns || vulns.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-500">Nenhuma vulnerabilidade crítica encontrada na base.</td></tr>`;
        return;
      }

      tbody.innerHTML = vulns.map((v, idx) => `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="font-bold text-slate-400">#${idx + 1}</td>
          <td class="font-mono text-xs text-slate-400">${v.plugin_id}</td>
          <td>
            <div class="font-medium text-slate-100">${v.plugin_name}</div>
            <div class="text-xs text-slate-400 mt-0.5 line-clamp-1">${v.synopsis || ''}</div>
          </td>
          <td>${this.formatCveBadge(v.cve, v.cve_list, v.cve_count)}</td>
          <td>
            <span class="badge-critical px-2 py-0.5 rounded text-xs font-bold">CVSS ${v.cvss_v3 ? v.cvss_v3.toFixed(1) : '9.8'}</span>
          </td>
          <td class="text-center">
            <span class="px-2.5 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700 text-xs font-bold">${v.affected_hosts_count} Hosts</span>
          </td>
          <td>
            ${v.exploit_available ? `<span class="badge-exploit px-2 py-0.5 rounded text-xs font-bold" title="${v.exploit_frameworks || 'Exploit disponível'}">SIM (${v.exploit_frameworks ? v.exploit_frameworks.split(',')[0] : 'Exploit'})</span>` : '<span class="text-slate-500 text-xs">Não</span>'}
          </td>
          <td class="text-right">
            <button onclick="App.openPluginSolutionModal('${v.plugin_id}')" class="px-3 py-1 text-xs font-medium rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 hover:bg-sky-500/20 cursor-pointer">Ver Solução</button>
          </td>
        </tr>
      `).join('');
      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-rose-400">Erro ao carregar dados: ${e.message}</td></tr>`;
    }
  },

  // --- TOP 20 HOSTS WITH EXPLOITS VIEW ---
  async loadTop20HostsData() {
    const groupId = this.state.selectedAssetGroupId || null;
    const tbody = document.getElementById('top20hosts-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400">Carregando Top 20 Hosts com Exploits...</td></tr>`;

    try {
      const hosts = await API.getTopExploits(groupId, 20);
      const countEl = document.getElementById('top20-count');
      if (countEl) countEl.textContent = `${hosts.length} Hosts Prioritários`;

      if (!hosts || hosts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-500">Nenhum host com vulnerabilidades críticas e exploits cadastrado.</td></tr>`;
        return;
      }

      tbody.innerHTML = hosts.map((h, idx) => {
        const score = Number(h.risk_score || 0);
        let riskBadgeClass = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700';
        if (score >= 120) {
          riskBadgeClass = 'bg-rose-50 text-rose-700 dark:bg-rose-950/50 dark:text-rose-300 border-rose-200 dark:border-rose-800/60';
        } else if (score >= 60) {
          riskBadgeClass = 'bg-orange-50 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300 border-orange-200 dark:border-orange-800/60';
        } else if (score >= 20) {
          riskBadgeClass = 'bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-800/60';
        }

        return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="font-bold text-slate-400">#${idx + 1}</td>
          <td>
            <div class="font-bold text-sky-400 font-mono text-sm">${h.ip_address}</div>
            <div class="text-xs text-slate-400">${h.hostname || 'Hostname não detectado'}</div>
          </td>
          <td class="text-xs text-slate-300">${h.asset_group_name || '-'}</td>
          <td class="text-xs text-slate-400">${h.os || 'Linux/Windows'}</td>
          <td>
            <span class="badge-critical px-2.5 py-1 rounded text-xs font-extrabold">${h.exploitable_critical_count} Críticas c/ Exploit</span>
          </td>
          <td class="text-xs text-slate-300">
            <span class="text-rose-400 font-bold">${h.critical_count}</span> Crít / <span class="text-orange-400 font-bold">${h.high_count}</span> Altas
          </td>
          <td>
            <span class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-extrabold font-mono border ${riskBadgeClass}">${score.toFixed(1)}</span>
          </td>
          <td class="text-right">
            <button onclick="App.openHostModal(${h.host_id})" class="px-3 py-1.5 text-xs font-medium rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 hover:bg-sky-500/20 cursor-pointer">Analisar Host</button>
          </td>
        </tr>
      `;
      }).join('');
      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-rose-400">Erro ao carregar dados: ${e.message}</td></tr>`;
    }
  },

  // --- INVENTORY MODULE ---
  async loadInventoryData() {
    const tbody = document.getElementById('inventory-tbody');
    if (!tbody) return;

    tbody.innerHTML = `<tr><td colspan="10" class="text-center py-10 text-slate-400">
      <div class="inline-flex items-center space-x-2">
        <i data-lucide="loader-2" class="w-5 h-5 animate-spin text-sky-500"></i>
        <span>Carregando inventário de hosts...</span>
      </div>
    </td></tr>`;
    this.refreshIcons();

    const assetGroupId = this.state.selectedAssetGroupId || '';
    const search = document.getElementById('inventory-search-input')?.value.trim() || '';
    const severityFilter = document.getElementById('inventory-sev-filter')?.value || '';
    const sortVal = document.getElementById('inventory-sort-filter')?.value || 'risk_score_desc';
    
    let sortBy = 'risk_score';
    let sortOrder = 'desc';
    if (sortVal === 'risk_score_asc') {
      sortBy = 'risk_score';
      sortOrder = 'asc';
    } else if (sortVal === 'critical_desc') {
      sortBy = 'critical_count';
      sortOrder = 'desc';
    } else if (sortVal === 'high_desc') {
      sortBy = 'high_count';
      sortOrder = 'desc';
    } else if (sortVal === 'ip_asc') {
      sortBy = 'ip_address';
      sortOrder = 'asc';
    } else if (sortVal === 'ip_desc') {
      sortBy = 'ip_address';
      sortOrder = 'desc';
    } else if (sortVal === 'hostname_asc') {
      sortBy = 'hostname';
      sortOrder = 'asc';
    } else if (sortVal === 'os_asc') {
      sortBy = 'os';
      sortOrder = 'asc';
    }

    const page = this.state.inventoryPage || 1;
    const pageSize = this.state.inventoryPageSize || 50;

    try {
      const res = await API.listInventory({
        asset_group_id: assetGroupId,
        search,
        severity_filter: severityFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
        page,
        page_size: pageSize
      });

      this.state.inventoryList = res.items || [];
      this.state.inventoryStats = res.stats || null;
      this.state.inventoryTotalCount = res.total || 0;
      this.state.inventoryTotalPages = res.total_pages || 1;
      this.state.inventoryPage = res.page || 1;

      // Update KPI counters
      const kpiHosts = document.getElementById('kpi-inv-hosts');
      const kpiCritHosts = document.getElementById('kpi-inv-crit-hosts');
      const kpiTotalVulns = document.getElementById('kpi-inv-total-vulns');
      const kpiCritCount = document.getElementById('kpi-inv-crit-count');
      const kpiHighCount = document.getElementById('kpi-inv-high-count');
      const kpiMedCount = document.getElementById('kpi-inv-med-count');
      const kpiLowCount = document.getElementById('kpi-inv-low-count');
      const kpiAvgRisk = document.getElementById('kpi-inv-avg-risk');
      const kpiMaxRisk = document.getElementById('kpi-inv-max-risk');
      const kpiExploitsCount = document.getElementById('kpi-inv-exploits-count');
      const badgeCount = document.getElementById('inventory-count-badge');

      if (res.stats) {
        if (kpiHosts) kpiHosts.textContent = Number(res.stats.total_hosts || 0).toLocaleString();
        if (kpiCritHosts) kpiCritHosts.textContent = Number(res.stats.hosts_with_critical || 0).toLocaleString();
        if (kpiTotalVulns) kpiTotalVulns.textContent = Number(res.stats.total_vulns || 0).toLocaleString();
        if (kpiCritCount) kpiCritCount.textContent = Number(res.stats.total_critical || 0).toLocaleString();
        if (kpiHighCount) kpiHighCount.textContent = Number(res.stats.total_high || 0).toLocaleString();
        if (kpiMedCount) kpiMedCount.textContent = Number(res.stats.total_medium || 0).toLocaleString();
        if (kpiLowCount) kpiLowCount.textContent = Number(res.stats.total_low || 0).toLocaleString();
        if (kpiAvgRisk) kpiAvgRisk.textContent = Number(res.stats.avg_risk_score || 0).toFixed(1);
        if (kpiMaxRisk) kpiMaxRisk.textContent = Number(res.stats.max_risk_score || 0).toFixed(1);
        if (kpiExploitsCount) kpiExploitsCount.textContent = Number(res.stats.hosts_with_exploits || 0).toLocaleString();
      }
      if (badgeCount) {
        badgeCount.textContent = `${Number(res.total || 0).toLocaleString()} Hosts Mapeados`;
      }

      // Render rows
      if (!res.items || res.items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center py-10 text-slate-500">
          <div class="flex flex-col items-center justify-center space-y-2">
            <i data-lucide="inbox" class="w-8 h-8 text-slate-400"></i>
            <span class="text-sm">Nenhum host encontrado para os filtros selecionados.</span>
          </div>
        </td></tr>`;
        this.renderInventoryPagination(res);
        this.refreshIcons();
        return;
      }

      tbody.innerHTML = res.items.map(h => {
        const score = Number(h.risk_score || 0);
        let riskBadgeClass = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700';
        if (score >= 120) {
          riskBadgeClass = 'bg-rose-50 text-rose-700 dark:bg-rose-950/50 dark:text-rose-300 border-rose-200 dark:border-rose-800/60 font-bold';
        } else if (score >= 60) {
          riskBadgeClass = 'bg-orange-50 text-orange-700 dark:bg-orange-950/50 dark:text-orange-300 border-orange-200 dark:border-orange-800/60 font-bold';
        } else if (score >= 20) {
          riskBadgeClass = 'bg-amber-50 text-amber-700 dark:bg-amber-950/50 dark:text-amber-300 border-amber-200 dark:border-amber-800/60 font-bold';
        }

        const osDisplay = h.os ? this.escapeHtml(h.os) : '<span class="text-slate-400 italic text-[11px]">Não detectado</span>';
        const hostnameDisplay = h.hostname ? this.escapeHtml(h.hostname) : '<span class="text-slate-400 italic text-[11px]">Não detectado</span>';
        const groupDisplay = h.asset_group_name ? this.escapeHtml(h.asset_group_name) : '-';

        return `
          <tr class="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition">
            <td>
              <div class="flex items-center space-x-2">
                <i data-lucide="monitor" class="w-4 h-4 text-slate-400 shrink-0"></i>
                <a href="javascript:void(0)" onclick="App.openHostModal(${h.id})" class="font-mono font-bold text-sky-600 dark:text-sky-400 hover:underline text-xs" title="Ver vulnerabilidades deste host">
                  ${this.escapeHtml(h.ip_address)}
                </a>
              </div>
            </td>
            <td>
              <div class="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate max-w-[200px]" title="${h.hostname || ''}">
                ${hostnameDisplay}
              </div>
            </td>
            <td>
              <div class="text-xs text-slate-600 dark:text-slate-300 truncate max-w-xs" title="${h.os || ''}">
                ${osDisplay}
              </div>
            </td>
            <td>
              <span class="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700 truncate max-w-[160px]" title="${h.asset_group_name || ''}">
                ${groupDisplay}
              </span>
            </td>
            <td class="text-center">
              <span class="inline-block min-w-[28px] px-2 py-0.5 rounded text-xs font-extrabold ${h.critical_count > 0 ? 'bg-red-100 text-red-700 dark:bg-red-950/70 dark:text-red-300 border border-red-200 dark:border-red-800' : 'text-slate-400 bg-slate-100 dark:bg-slate-800/60'}">${h.critical_count}</span>
            </td>
            <td class="text-center">
              <span class="inline-block min-w-[28px] px-2 py-0.5 rounded text-xs font-extrabold ${h.high_count > 0 ? 'bg-orange-100 text-orange-700 dark:bg-orange-950/70 dark:text-orange-300 border border-orange-200 dark:border-orange-800' : 'text-slate-400 bg-slate-100 dark:bg-slate-800/60'}">${h.high_count}</span>
            </td>
            <td class="text-center">
              <span class="inline-block min-w-[28px] px-2 py-0.5 rounded text-xs font-extrabold ${h.medium_count > 0 ? 'bg-amber-100 text-amber-700 dark:bg-amber-950/70 dark:text-amber-300 border border-amber-200 dark:border-amber-800' : 'text-slate-400 bg-slate-100 dark:bg-slate-800/60'}">${h.medium_count}</span>
            </td>
            <td class="text-center">
              <span class="inline-block min-w-[28px] px-2 py-0.5 rounded text-xs font-extrabold ${h.low_count > 0 ? 'bg-blue-100 text-blue-700 dark:bg-blue-950/70 dark:text-blue-300 border border-blue-200 dark:border-blue-800' : 'text-slate-400 bg-slate-100 dark:bg-slate-800/60'}">${h.low_count}</span>
            </td>
            <td class="text-center">
              <span class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-mono border ${riskBadgeClass}">
                ${score.toFixed(1)}
              </span>
            </td>
            <td class="text-right whitespace-nowrap">
              <div class="flex items-center justify-end space-x-1.5">
                <button onclick="App.openHostModal(${h.id})" class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-sky-50 dark:bg-sky-950/50 text-sky-700 dark:text-sky-300 border border-sky-200 dark:border-sky-800 hover:bg-sky-100 dark:hover:bg-sky-900/60 cursor-pointer flex items-center space-x-1" title="Ver vulnerabilidades deste host">
                  <i data-lucide="shield-alert" class="w-3.5 h-3.5"></i>
                  <span>Vulnerabilidades</span>
                </button>
                <button onclick="App.filterVulnsByHost('${this.escapeHtml(h.ip_address)}')" class="p-1 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 rounded hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer" title="Filtrar no Explorador de Vulnerabilidades">
                  <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');

      this.renderInventoryPagination(res);
      this.refreshIcons();
    } catch (e) {
      console.error('Error loading inventory data:', e);
      tbody.innerHTML = `<tr><td colspan="10" class="text-center py-8 text-rose-500">Erro ao carregar inventário: ${this.escapeHtml(e.message)}</td></tr>`;
    }
  },

  renderInventoryPagination(res) {
    const total = res.total || 0;
    const page = res.page || 1;
    const pageSize = res.page_size || 50;
    const totalPages = res.total_pages || 1;

    const pageInfo = document.getElementById('inventory-page-info');
    const prevBtn = document.getElementById('inventory-prev-btn');
    const nextBtn = document.getElementById('inventory-next-btn');
    const pillsContainer = document.getElementById('inventory-page-pills');

    if (pageInfo) {
      if (total === 0) {
        pageInfo.textContent = 'Mostrando 0 de 0 hosts';
      } else {
        const start = (page - 1) * pageSize + 1;
        const end = Math.min(total, page * pageSize);
        pageInfo.textContent = `Mostrando ${start.toLocaleString()} a ${end.toLocaleString()} de ${total.toLocaleString()} hosts`;
      }
    }

    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= totalPages;

    if (pillsContainer) {
      pillsContainer.innerHTML = '';
      if (totalPages <= 1) return;

      const maxPills = 5;
      let startPill = Math.max(1, page - Math.floor(maxPills / 2));
      let endPill = Math.min(totalPages, startPill + maxPills - 1);
      if (endPill - startPill + 1 < maxPills) {
        startPill = Math.max(1, endPill - maxPills + 1);
      }

      for (let p = startPill; p <= endPill; p++) {
        const btn = document.createElement('button');
        btn.textContent = String(p);
        btn.className = p === page
          ? 'px-3 py-1 rounded-lg bg-sky-600 text-white font-bold text-xs cursor-pointer shadow-xs'
          : 'px-3 py-1 rounded-lg bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs cursor-pointer transition';
        btn.onclick = () => this.setInventoryPage(p);
        pillsContainer.appendChild(btn);
      }
    }
  },

  setInventoryPage(page) {
    if (page < 1 || (this.state.inventoryTotalPages && page > this.state.inventoryTotalPages)) return;
    this.state.inventoryPage = page;
    this.loadInventoryData();
  },

  clearInventoryFilters() {
    const sInput = document.getElementById('inventory-search-input');
    const sevFilter = document.getElementById('inventory-sev-filter');
    const sortFilter = document.getElementById('inventory-sort-filter');
    if (sInput) sInput.value = '';
    if (sevFilter) sevFilter.value = '';
    if (sortFilter) sortFilter.value = 'risk_score_desc';
    this.state.inventoryPage = 1;
    this.loadInventoryData();
  },

  async exportInventoryCSV() {
    try {
      const assetGroupId = this.state.selectedAssetGroupId || '';
      const search = document.getElementById('inventory-search-input')?.value.trim() || '';
      const severityFilter = document.getElementById('inventory-sev-filter')?.value || '';
      const sortVal = document.getElementById('inventory-sort-filter')?.value || 'risk_score_desc';

      let sortBy = 'risk_score';
      let sortOrder = 'desc';
      if (sortVal === 'risk_score_asc') {
        sortBy = 'risk_score';
        sortOrder = 'asc';
      } else if (sortVal === 'critical_desc') {
        sortBy = 'critical_count';
        sortOrder = 'desc';
      } else if (sortVal === 'high_desc') {
        sortBy = 'high_count';
        sortOrder = 'desc';
      } else if (sortVal === 'ip_asc') {
        sortBy = 'ip_address';
        sortOrder = 'asc';
      } else if (sortVal === 'ip_desc') {
        sortBy = 'ip_address';
        sortOrder = 'desc';
      } else if (sortVal === 'hostname_asc') {
        sortBy = 'hostname';
        sortOrder = 'asc';
      } else if (sortVal === 'os_asc') {
        sortBy = 'os';
        sortOrder = 'asc';
      }

      const res = await API.listInventory({
        asset_group_id: assetGroupId,
        search,
        severity_filter: severityFilter,
        sort_by: sortBy,
        sort_order: sortOrder,
        page: 1,
        page_size: 5000
      });

      const hosts = res.items || [];
      if (hosts.length === 0) {
        alert('Nenhum host para exportar com os filtros atuais.');
        return;
      }

      const headers = ['IP', 'Hostname', 'Sistema Operacional', 'Grupo de Ativos', 'Criticas', 'Altas', 'Medias', 'Baixas', 'Risk Score'];
      const rows = hosts.map(h => [
        `"${(h.ip_address || '').replace(/"/g, '""')}"`,
        `"${(h.hostname || '').replace(/"/g, '""')}"`,
        `"${(h.os || '').replace(/"/g, '""')}"`,
        `"${(h.asset_group_name || '').replace(/"/g, '""')}"`,
        h.critical_count || 0,
        h.high_count || 0,
        h.medium_count || 0,
        h.low_count || 0,
        Number(h.risk_score || 0).toFixed(1)
      ]);

      const csvContent = '\uFEFF' + [headers.join(';'), ...rows.map(r => r.join(';'))].join('\r\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `inventario_hosts_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(`Erro ao exportar CSV de Inventário: ${e.message}`);
    }
  },

  filterVulnsByHost(ip) {
    if (!ip) return;
    this.navigate('vulnerabilities');
    const hostFilter = document.getElementById('vuln-host-filter');
    if (hostFilter) {
      hostFilter.value = ip;
      this.state.vulnPage = 1;
      this.loadVulnerabilitiesList();
    }
  },

  filterVulnsFromModal() {
    const ip = this.state.inventoryCurrentHostIp;
    this.closeHostModal();
    if (ip) {
      this.filterVulnsByHost(ip);
    }
  },

  // --- EXECUTIVE REPORTS MODULE ---
  async loadReportsData() {
    // 1. Preenche dropdown de Grupos com hierarquia
    const groupSelect = document.getElementById('report-param-group');
    if (groupSelect) {
      const currentVal = groupSelect.value;
      groupSelect.innerHTML = this.getHierarchicalGroupOptions(true, 'Todos os Grupos de Ativos');
      if (currentVal) {
        groupSelect.value = currentVal;
      } else if (this.state.selectedAssetGroupId) {
        groupSelect.value = String(this.state.selectedAssetGroupId);
      }
    }

    // 2. Data de Emissão Padrão (agora)
    const emissionInput = document.getElementById('report-param-emission-date');
    if (emissionInput) {
      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      emissionInput.value = `${pad(now.getDate())}/${pad(now.getMonth() + 1)}/${now.getFullYear()} ${pad(now.getHours())}:${pad(now.getMinutes())}`;
    }

    // 3. Período Padrão
    const periodInput = document.getElementById('report-param-period');
    if (periodInput) {
      const now = new Date();
      const meses = ['Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho', 'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'];
      periodInput.value = `Ciclo de Escaneamento de ${meses[now.getMonth()]}/${now.getFullYear()}`;
    }

    // 4. Carrega Scans do grupo selecionado
    await this.onReportGroupChange();
    this.refreshIcons();
  },

  async onReportGroupChange() {
    const groupSelect = document.getElementById('report-param-group');
    const scanSelect = document.getElementById('report-param-scan');
    const hintEl = document.getElementById('report-group-scan-hint');
    if (!scanSelect) return;

    const groupId = groupSelect ? groupSelect.value : '';
    scanSelect.innerHTML = `<option value="">Scan mais recente consolidado</option>`;

    try {
      let scans = [];
      if (groupId) {
        scans = await API.getScansByGroup(groupId);
      } else {
        scans = await API.listScans();
      }

      if (scans && scans.length > 0) {
        const sortedScans = [...scans].sort((a, b) => new Date(b.scan_date || 0) - new Date(a.scan_date || 0));
        sortedScans.forEach(s => {
          const opt = document.createElement('option');
          opt.value = s.id;
          const dt = s.scan_date ? new Date(s.scan_date).toLocaleDateString('pt-BR') : '';
          const grpName = s.asset_group ? s.asset_group.name : (s.asset_group_id ? `Grupo #${s.asset_group_id}` : 'Sem Grupo');
          opt.textContent = `${s.scan_name} (${s.scan_type === 'baseline' ? 'Antes' : 'Reteste'}) - [${grpName}] ${dt}`;
          opt.dataset.scanDate = s.scan_date || '';
          opt.dataset.groupName = grpName;
          scanSelect.appendChild(opt);
        });

        if (hintEl) {
          if (groupId) {
            hintEl.className = 'md:col-span-3 text-xs p-2.5 rounded-lg border bg-emerald-50 dark:bg-emerald-950/30 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800 flex items-center space-x-2';
            hintEl.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 flex-shrink-0"></i><span>Grupo com <strong>${scans.length}</strong> varredura(s) registrada(s). Selecione uma específica ou utilize a mais recente.</span>`;
          } else {
            hintEl.className = 'md:col-span-3 text-xs p-2.5 rounded-lg border bg-slate-50 dark:bg-slate-900/40 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-800 flex items-center space-x-2';
            hintEl.innerHTML = `<i data-lucide="info" class="w-4 h-4 flex-shrink-0"></i><span>Visão Global Consolidada: o relatório consolidará as últimas varreduras de todos os grupos ativos (${scans.length} varreduras no sistema).</span>`;
          }
          hintEl.classList.remove('hidden');
        }
      } else {
        if (hintEl) {
          hintEl.className = 'md:col-span-3 text-xs p-2.5 rounded-lg border bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-200 border-amber-200 dark:border-amber-800 flex items-center space-x-2';
          hintEl.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4 flex-shrink-0"></i><span>Atenção: Este grupo de ativos ainda não possui nenhum scan finalizado importado. O relatório indicará dados zerados até que um scan seja importado.</span>`;
          hintEl.classList.remove('hidden');
        }
      }
    } catch (e) {
      console.warn('Não foi possível listar scans para o grupo:', e);
    }
    this.refreshIcons();
  },

  onReportScanChange() {
    const scanSelect = document.getElementById('report-param-scan');
    const periodInput = document.getElementById('report-param-period');
    if (!scanSelect || !periodInput) return;

    const selectedOption = scanSelect.options[scanSelect.selectedIndex];
    if (selectedOption && selectedOption.dataset && selectedOption.dataset.scanDate) {
      try {
        const d = new Date(selectedOption.dataset.scanDate);
        const meses = ['Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho', 'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'];
        periodInput.value = `Ciclo de Escaneamento de ${meses[d.getMonth()]}/${d.getFullYear()} (${d.toLocaleDateString('pt-BR')})`;
      } catch (e) {}
    }
  },

  openExecutiveReport() {
    const groupSelect = document.getElementById('report-param-group');
    const scanSelect = document.getElementById('report-param-scan');
    const periodInput = document.getElementById('report-param-period');
    const teamInput = document.getElementById('report-param-team');
    const emissionInput = document.getElementById('report-param-emission-date');
    const classifSelect = document.getElementById('report-param-classification');

    const groupId = groupSelect ? groupSelect.value : '';
    const scanId = scanSelect ? scanSelect.value : '';
    const period = periodInput ? periodInput.value.trim() : '';
    const team = teamInput ? teamInput.value.trim() : '';
    const emissionDate = emissionInput ? emissionInput.value.trim() : '';
    const classification = classifSelect ? classifSelect.value : '';

    const qs = new URLSearchParams();
    if (groupId) qs.append('asset_group_id', groupId);
    if (scanId) qs.append('scan_id', scanId);
    if (period) qs.append('period', period);
    if (team) qs.append('team', team);
    if (emissionDate) qs.append('emission_date', emissionDate);
    if (classification) qs.append('classification', classification);

    const token = API.getToken();
    if (token) {
      qs.append('token', token);
    }

    const reportUrl = `/report-summary.html?${qs.toString()}`;
    window.open(reportUrl, '_blank');
  },

  openTechnicalReport() {
    const groupSelect = document.getElementById('report-param-group');
    const scanSelect = document.getElementById('report-param-scan');
    const periodInput = document.getElementById('report-param-period');
    const teamInput = document.getElementById('report-param-team');
    const emissionInput = document.getElementById('report-param-emission-date');
    const classifSelect = document.getElementById('report-param-classification');

    const groupId = groupSelect ? groupSelect.value : '';
    const scanId = scanSelect ? scanSelect.value : '';
    const period = periodInput ? periodInput.value.trim() : '';
    const team = teamInput ? teamInput.value.trim() : '';
    const emissionDate = emissionInput ? emissionInput.value.trim() : '';
    const classification = classifSelect ? classifSelect.value : '';

    const qs = new URLSearchParams();
    if (groupId) qs.append('asset_group_id', groupId);
    if (scanId) qs.append('scan_id', scanId);
    if (period) qs.append('period', period);
    if (team) qs.append('team', team);
    if (emissionDate) qs.append('emission_date', emissionDate);
    if (classification) qs.append('classification', classification);

    const token = API.getToken();
    if (token) {
      qs.append('token', token);
    }

    const reportUrl = `/report-technical.html?${qs.toString()}`;
    window.open(reportUrl, '_blank');
  },

  openSlaAuditReport() {
    const groupSelect = document.getElementById('report-param-group');
    const scanSelect = document.getElementById('report-param-scan');
    const periodInput = document.getElementById('report-param-period');
    const teamInput = document.getElementById('report-param-team');
    const emissionInput = document.getElementById('report-param-emission-date');
    const classifSelect = document.getElementById('report-param-classification');

    const groupId = groupSelect ? groupSelect.value : '';
    const scanId = scanSelect ? scanSelect.value : '';
    const period = periodInput ? periodInput.value.trim() : '';
    const team = teamInput ? teamInput.value.trim() : '';
    const emissionDate = emissionInput ? emissionInput.value.trim() : '';
    const classification = classifSelect ? classifSelect.value : '';

    const qs = new URLSearchParams();
    if (groupId) qs.append('asset_group_id', groupId);
    if (scanId) qs.append('scan_id', scanId);
    if (period) qs.append('period', period);
    if (team) qs.append('team', team);
    if (emissionDate) qs.append('emission_date', emissionDate);
    if (classification) qs.append('classification', classification);

    const token = API.getToken();
    if (token) {
      qs.append('token', token);
    }

    const reportUrl = `/report-sla-audit.html?${qs.toString()}`;
    window.open(reportUrl, '_blank');
  },

  // --- ASSET GROUPS MANAGEMENT ---
  async loadAssetGroupsTable() {
    const tbody = document.getElementById('asset-groups-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">Carregando grupos de ativos...</td></tr>`;

    try {
      const groups = await API.listAssetGroups();
      this.state.assetGroups = groups || [];

      if (groups.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-500">Nenhum grupo cadastrado. Cadastre um novo grupo para organizar os scans.</td></tr>`;
        return;
      }

      // Organize hierarchically for the table
      const sortedGroups = this.buildHierarchicalGroupList(groups);

      tbody.innerHTML = sortedGroups.map(g => {
        const depth = g.depth || g.level || 1;
        const lvl = g.level || depth;
        const isLevel1 = lvl === 1 || !g.parent_id;
        const isLevel2 = lvl === 2;
        const hasSubgroups = (g.subgroups_count || 0) > 0;

        let nameHtml = '';
        if (isLevel1) {
          nameHtml = `
            <div class="flex flex-col">
              <span class="font-bold text-sky-400 dark:text-sky-300 flex items-center space-x-1.5 text-sm">
                <i data-lucide="building-2" class="w-4 h-4 text-sky-400"></i>
                <span>${g.name}</span>
              </span>
              ${hasSubgroups 
                ? `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-500/20 text-sky-300 border border-sky-500/30 w-fit">🏢 Nível 1 - Grupo Corporativo (${g.subgroups_count} subgrupos subordinados)</span>` 
                : `<span class="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-500/20 text-slate-400 border border-slate-500/30 w-fit">🏢 Nível 1 - Grupo Independente</span>`}
            </div>`;
        } else if (isLevel2) {
          nameHtml = `
            <div class="flex flex-col pl-4 border-l-2 border-slate-700 ml-2">
              <span class="font-semibold text-teal-300 flex items-center space-x-1.5 text-xs">
                <i data-lucide="corner-down-right" class="w-3.5 h-3.5 text-teal-400"></i>
                <span>${g.name}</span>
              </span>
              <div class="flex items-center space-x-2 mt-1">
                <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-teal-500/15 text-teal-300 border border-teal-500/30 w-fit">
                  📍 Nível 2 - Subgrupo${hasSubgroups ? ` (${g.subgroups_count} subordinados)` : ''}
                </span>
                <span class="text-[10px] text-slate-400">
                  Subordinado a: <strong class="text-slate-300">${g.parent_name || 'Grupo Superior'}</strong>
                </span>
              </div>
            </div>`;
        } else {
          // Level 3 or deeper
          const indentPadding = Math.min((lvl - 1) * 1.25, 3.75);
          nameHtml = `
            <div class="flex flex-col border-l-2 border-amber-600/60 ml-3" style="padding-left: ${indentPadding}rem;">
              <span class="font-medium text-amber-300 flex items-center space-x-1.5 text-xs">
                <i data-lucide="corner-down-right" class="w-3.5 h-3.5 text-amber-400"></i>
                <span>${g.name}</span>
              </span>
              <div class="flex items-center space-x-2 mt-1">
                <span class="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30 w-fit">
                  ⤷ Nível ${lvl} - Sub-subgrupo / Área${hasSubgroups ? ` (${g.subgroups_count} subordinados)` : ''}
                </span>
                <span class="text-[10px] text-slate-400">
                  Caminho: <strong class="text-slate-300">${g.hierarchy_path || g.parent_name || ''}</strong>
                </span>
              </div>
            </div>`;
        }

        const consolidatedTooltip = hasSubgroups ? `Consolidado: métricas do grupo e seus ${g.subgroups_count} subgrupos subordinados` : 'Métricas exclusivas deste grupo';

        return `
          <tr class="hover:bg-slate-800/40 transition">
            <td>${nameHtml}</td>
            <td class="text-xs text-slate-400 font-mono">${g.network_range || 'Não especificada'}</td>
            <td class="text-xs text-slate-300">${g.owner || 'Não informado'}</td>
            <td class="text-center">
              <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700 font-semibold" title="${consolidatedTooltip}">${g.total_scans || 0} Scans</span>
            </td>
            <td class="text-center">
              <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700 font-semibold" title="${consolidatedTooltip}">${g.total_hosts || 0} Hosts</span>
            </td>
            <td class="text-center">
              <span class="badge-critical px-2 py-0.5 rounded text-xs font-bold" title="${consolidatedTooltip}">${g.critical_count || 0}</span> / 
              <span class="badge-high px-2 py-0.5 rounded text-xs font-bold" title="${consolidatedTooltip}">${g.high_count || 0}</span>
            </td>
            <td class="text-right space-x-1">
              ${(this.state.user?.role === 'admin' || this.state.user?.role === 'analyst') ? `<button onclick="App.openEditAssetGroupModal(${g.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 cursor-pointer">Editar</button>` : ''}
              ${this.state.user?.role === 'admin' ? `<button onclick="App.handleDeleteAssetGroup(${g.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 cursor-pointer">Excluir</button>` : ''}
              ${this.state.user?.role === 'auditor' ? `<span class="text-xs text-slate-500 italic">Somente Leitura</span>` : ''}
            </td>
          </tr>
        `;
      }).join('');
      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-rose-400">Erro: ${e.message}</td></tr>`;
    }
  },

  openCreateAssetGroupModal() {
    document.getElementById('group-modal-title').textContent = 'Novo Grupo de Ativos & Tratamento';
    document.getElementById('group-id').value = '';
    document.getElementById('group-name').value = '';
    document.getElementById('group-desc').value = '';
    document.getElementById('group-network').value = '';
    document.getElementById('group-owner').value = '';
    document.getElementById('group-sla-crit').value = '7';
    document.getElementById('group-sla-high').value = '15';

    const parentSelect = document.getElementById('group-parent-id');
    if (parentSelect) {
      const groups = this.state.assetGroups || [];
      const hierarchical = this.buildHierarchicalGroupList(groups);
      let opts = '<option value="">Nenhum (Criar como Grupo Corporativo / Raiz - Nível 1)</option>';
      hierarchical.forEach(r => {
        const depth = r.depth || 1;
        const lvl = r.level || depth;
        let indent = '';
        if (depth === 2) {
          indent = '&nbsp;'.repeat(8);
        } else if (depth >= 3) {
          indent = '&nbsp;'.repeat(8 + (depth - 2) * 10);
        }
        const icon = depth === 1 ? '🏢 ' : depth === 2 ? '📍 ' : '⤷ ';
        const levelLabel = lvl === 1 ? 'Nível 1' : lvl === 2 ? 'Nível 2' : `Nível ${lvl}`;
        opts += `<option value="${r.id}">${indent}${icon}[${levelLabel}] ${r.name}</option>`;
      });
      parentSelect.innerHTML = opts;
      parentSelect.value = '';
    }

    document.getElementById('asset-group-modal').classList.remove('hidden');
    this.refreshIcons();
  },

  openEditAssetGroupModal(groupId) {
    const group = this.state.assetGroups.find(g => g.id === groupId);
    if (!group) return;

    document.getElementById('group-modal-title').textContent = 'Editar Grupo de Ativos';
    document.getElementById('group-id').value = group.id;
    document.getElementById('group-name').value = group.name;
    document.getElementById('group-desc').value = group.description || '';
    document.getElementById('group-network').value = group.network_range || '';
    document.getElementById('group-owner').value = group.owner || '';
    document.getElementById('group-sla-crit').value = group.sla_critical_days;
    document.getElementById('group-sla-high').value = group.sla_high_days;

    const parentSelect = document.getElementById('group-parent-id');
    if (parentSelect) {
      const groups = this.state.assetGroups || [];
      const descendantIds = new Set(this.getGroupDescendantIds(groupId, groups));
      descendantIds.add(groupId);

      const eligible = groups.filter(g => !descendantIds.has(g.id));
      const hierarchical = this.buildHierarchicalGroupList(eligible);

      let opts = '<option value="">Nenhum (Grupo Corporativo / Raiz - Nível 1)</option>';
      hierarchical.forEach(r => {
        const depth = r.depth || 1;
        const lvl = r.level || depth;
        let indent = '';
        if (depth === 2) {
          indent = '&nbsp;'.repeat(8);
        } else if (depth >= 3) {
          indent = '&nbsp;'.repeat(8 + (depth - 2) * 10);
        }
        const icon = depth === 1 ? '🏢 ' : depth === 2 ? '📍 ' : '⤷ ';
        const levelLabel = lvl === 1 ? 'Nível 1' : lvl === 2 ? 'Nível 2' : `Nível ${lvl}`;
        opts += `<option value="${r.id}">${indent}${icon}[${levelLabel}] ${r.name}</option>`;
      });
      parentSelect.innerHTML = opts;
      parentSelect.value = group.parent_id || '';
    }

    document.getElementById('asset-group-modal').classList.remove('hidden');
    this.refreshIcons();
  },

  closeAssetGroupModal() {
    document.getElementById('asset-group-modal').classList.add('hidden');
  },

  async handleSaveAssetGroup(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (this.state.user?.role === 'auditor') {
      alert('Auditores ISO possuem permissão apenas de leitura.');
      return;
    }
    if (this._isSavingAssetGroup) return;
    this._isSavingAssetGroup = true;

    const submitBtn = document.querySelector('#asset-group-form button[type="submit"]');
    const originalText = submitBtn ? submitBtn.textContent : 'Salvar Grupo';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = 'Salvando...';
    }

    const id = document.getElementById('group-id').value;
    const parentVal = document.getElementById('group-parent-id')?.value;
    const data = {
      name: document.getElementById('group-name').value.trim(),
      description: document.getElementById('group-desc').value.trim(),
      network_range: document.getElementById('group-network').value.trim(),
      owner: document.getElementById('group-owner').value.trim(),
      parent_id: parentVal ? parseInt(parentVal) : null,
      sla_critical_days: parseInt(document.getElementById('group-sla-crit').value) || 7,
      sla_high_days: parseInt(document.getElementById('group-sla-high').value) || 15
    };

    try {
      if (id) {
        await API.updateAssetGroup(id, data);
      } else {
        await API.createAssetGroup(data);
      }
      this.closeAssetGroupModal();
      await this.loadAssetGroups();
      this.loadAssetGroupsTable();
    } catch (err) {
      alert(`Erro ao salvar grupo: ${err.message}`);
    } finally {
      this._isSavingAssetGroup = false;
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
    }
  },

  async handleDeleteAssetGroup(groupId) {
    if (this.state.user?.role !== 'admin') {
      alert('Apenas Administradores Gerais podem excluir Grupos de Ativos.');
      return;
    }
    if (!confirm('Tem certeza que deseja excluir este Grupo de Ativos? Todos os scans e vulnerabilidades associados serão apagados permanentemente.')) {
      return;
    }
    try {
      await API.deleteAssetGroup(groupId);
      await this.loadAssetGroups();
      this.loadAssetGroupsTable();
    } catch (err) {
      alert(`Erro ao excluir: ${err.message}`);
    }
  },

  // --- COMPARATIVE (BEFORE VS AFTER - ISO 9001 PDCA) ---
  async loadComparativeSelectors() {
    const groupSelect = document.getElementById('comp-asset-group-select');
    if (groupSelect && groupSelect.value) {
      this.handleComparativeGroupChange(groupSelect.value);
    }
  },

  async handleComparativeGroupChange(groupId) {
    if (!groupId) return;
    const baselineSelect = document.getElementById('comp-baseline-select');
    const retestSelect = document.getElementById('comp-retest-select');

    if (baselineSelect) baselineSelect.innerHTML = '<option value="" disabled selected>Carregando scans...</option>';
    if (retestSelect) retestSelect.innerHTML = '<option value="" disabled selected>Carregando scans...</option>';

    try {
      const scans = await API.getScansByGroup(groupId);
      if (!scans || scans.length === 0) {
        if (baselineSelect) baselineSelect.innerHTML = '<option value="" disabled selected>Nenhum scan cadastrado neste grupo</option>';
        if (retestSelect) retestSelect.innerHTML = '<option value="" disabled selected>Nenhum scan cadastrado neste grupo</option>';
        return;
      }

      const baselineOptions = scans.map(s => {
        const d = this.formatDateBR(s.scan_date || s.created_at);
        const groupInfo = s.asset_group_name ? ` [${s.asset_group_name}]` : '';
        return `<option value="${s.id}">${s.scan_name} (${d})${groupInfo} - ${s.total_findings} vulns</option>`;
      }).join('');

      if (baselineSelect) baselineSelect.innerHTML = '<option value="" disabled selected>Selecione o Scan Anterior (Referência)...</option>' + baselineOptions;
      if (retestSelect) retestSelect.innerHTML = '<option value="" disabled selected>Selecione o Scan Mais Recente (Comparado)...</option>' + baselineOptions;

      // Default: baseline = oldest scan, retest = newest scan (if > 1 scan)
      const baselineScan = scans[0];
      const retestScan = scans.length > 1 ? scans[scans.length - 1] : scans[0];

      if (baselineScan && baselineSelect) baselineSelect.value = baselineScan.id;
      if (retestScan && retestSelect && retestScan.id !== baselineScan?.id) retestSelect.value = retestScan.id;

    } catch (e) {
      console.error('Error loading scans for comparative:', e);
    }
  },

  async handleRunComparative(e) {
    if (e && e.preventDefault) e.preventDefault();
    const baselineId = document.getElementById('comp-baseline-select')?.value;
    const retestId = document.getElementById('comp-retest-select')?.value;
    const resultsContainer = document.getElementById('comparative-results');
    const errorEl = document.getElementById('comp-error');

    if (errorEl) errorEl.classList.add('hidden');

    if (!baselineId || !retestId) {
      alert('Selecione ambos os scans (Anterior e Recente) para executar a comparação.');
      return;
    }
    if (baselineId === retestId) {
      alert('Selecione dois scans diferentes para comparação.');
      return;
    }

    try {
      const report = await API.getComparativeDiff(baselineId, retestId);
      this.state.comparativeReport = report;
      this.renderComparativeReport(report);
      if (resultsContainer) resultsContainer.classList.remove('hidden');
    } catch (err) {
      if (errorEl) {
        errorEl.textContent = err.message || 'Erro ao processar comparativo.';
        errorEl.classList.remove('hidden');
      }
    }
  },

  renderComparativeReport(report) {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal('comp-remediation-rate', `${(report.remediation_rate_percent || 0).toFixed(1)}%`);
    setVal('comp-risk-reduction', `${(report.risk_reduction_percent || 0).toFixed(1)}%`);
    setVal('comp-remediated-count', (report.remediated_count || 0).toLocaleString());
    setVal('comp-persisting-count', (report.persisting_count || 0).toLocaleString());
    setVal('comp-new-count', (report.new_count || 0).toLocaleString());
    setVal('comp-total-before', (report.total_before || 0).toLocaleString());
    setVal('comp-total-after', (report.total_after || 0).toLocaleString());

    const compCtx = document.getElementById('chart-comparative-diff');
    if (compCtx) {
      AppCharts.initComparativeChart(compCtx, report.severity_before || {}, report.severity_after || {});
    }

    // Update Category Dropdown Option Labels with Exact Counts
    const catSelect = document.getElementById('comp-category-filter');
    if (catSelect) {
      const remCount = (report.remediated_count || 0).toLocaleString();
      const perCount = (report.persisting_count || 0).toLocaleString();
      const newCount = (report.new_count || 0).toLocaleString();
      const totCount = ((report.remediated_count || 0) + (report.persisting_count || 0) + (report.new_count || 0)).toLocaleString();

      catSelect.innerHTML = `
        <option value="remediated">🟢 Vulnerabilidades Remediadas / Resolvidas (${remCount})</option>
        <option value="persisting">🟡 Vulnerabilidades Persistentes / Mantidas (${perCount})</option>
        <option value="new">🔴 Novas Vulnerabilidades / Regressões (${newCount})</option>
        <option value="all">📋 Todas as Categorias Combinadas (${totCount})</option>
      `;
      catSelect.value = this.comparativeState.category || 'remediated';
    }

    this.comparativeState.page = 1;
    this.renderComparativeDetailsTable();
    this.refreshIcons();
  },

  comparativeState: {
    page: 1,
    pageSize: 50,
    category: 'remediated',
    search: '',
    severity: ''
  },

  setComparativeCategory(category) {
    const filterSelect = document.getElementById('comp-category-filter');
    if (filterSelect) filterSelect.value = category;
    this.handleComparativeFilterChange();
  },

  handleComparativeFilterChange() {
    this.comparativeState.category = document.getElementById('comp-category-filter')?.value || 'remediated';
    this.comparativeState.search = document.getElementById('comp-search-input')?.value.trim().toLowerCase() || '';
    this.comparativeState.severity = document.getElementById('comp-sev-filter')?.value || '';
    this.comparativeState.page = 1;
    this.renderComparativeDetailsTable();
  },

  handleComparativePageChange(delta) {
    this.comparativeState.page += delta;
    if (this.comparativeState.page < 1) this.comparativeState.page = 1;
    this.renderComparativeDetailsTable();
  },

  renderComparativeDetailsTable() {
    const report = this.state.comparativeReport;
    const tbody = document.getElementById('comp-details-tbody');
    if (!tbody || !report) return;

    let items = [];
    const cat = this.comparativeState.category;

    if (cat === 'remediated') {
      items = (report.remediated_items || []).map(i => ({ ...i, diff_status: 'RESOLVIDA', badgeClass: 'badge-remediated' }));
    } else if (cat === 'persisting') {
      items = (report.persisting_items || []).map(i => ({ ...i, diff_status: 'PERSISTENTE', badgeClass: 'badge-persisting' }));
    } else if (cat === 'new') {
      items = (report.new_items || []).map(i => ({ ...i, diff_status: 'NOVA', badgeClass: 'badge-new' }));
    } else {
      const rem = (report.remediated_items || []).map(i => ({ ...i, diff_status: 'RESOLVIDA', badgeClass: 'badge-remediated' }));
      const per = (report.persisting_items || []).map(i => ({ ...i, diff_status: 'PERSISTENTE', badgeClass: 'badge-persisting' }));
      const nw = (report.new_items || []).map(i => ({ ...i, diff_status: 'NOVA', badgeClass: 'badge-new' }));
      items = [...rem, ...per, ...nw];
    }

    // Apply search and severity filters
    const search = this.comparativeState.search;
    const sev = this.comparativeState.severity;

    if (search) {
      items = items.filter(i => 
        (i.host_ip && i.host_ip.toLowerCase().includes(search)) ||
        (i.plugin_name && i.plugin_name.toLowerCase().includes(search)) ||
        (i.cve && i.cve.toLowerCase().includes(search)) ||
        (i.plugin_id && String(i.plugin_id).includes(search))
      );
    }

    if (sev) {
      items = items.filter(i => i.severity === sev);
    }

    const totalFiltered = items.length;
    const badgeEl = document.getElementById('comp-filtered-count-badge');
    if (badgeEl) badgeEl.textContent = `${totalFiltered.toLocaleString()} itens`;

    const pageSize = this.comparativeState.pageSize || 50;
    const totalPages = Math.ceil(totalFiltered / pageSize) || 1;
    if (this.comparativeState.page > totalPages) this.comparativeState.page = totalPages;
    const currentPage = this.comparativeState.page;

    const startIdx = (currentPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, totalFiltered);
    const paginatedItems = items.slice(startIdx, endIdx);

    // Update pagination controls
    const pageInfoEl = document.getElementById('comp-page-info');
    const pageTotalEl = document.getElementById('comp-page-total');
    const currPageEl = document.getElementById('comp-current-page');
    const prevBtn = document.getElementById('comp-prev-btn');
    const nextBtn = document.getElementById('comp-next-btn');

    if (pageInfoEl) pageInfoEl.textContent = totalFiltered === 0 ? '0' : `${(startIdx + 1).toLocaleString()} - ${endIdx.toLocaleString()}`;
    if (pageTotalEl) pageTotalEl.textContent = totalFiltered.toLocaleString();
    if (currPageEl) currPageEl.textContent = `${currentPage} / ${totalPages}`;
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;

    if (totalFiltered === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Nenhum apontamento encontrado com os filtros selecionados.</td></tr>`;
      return;
    }

    tbody.innerHTML = paginatedItems.map(item => `
      <tr class="hover:bg-slate-800/40 transition">
        <td><span class="${item.badgeClass} px-2 py-0.5 rounded text-xs font-bold">${item.diff_status}</span></td>
        <td class="font-mono text-sky-400 text-xs font-semibold">${item.host_ip}</td>
        <td>
          <div class="font-medium text-slate-200 text-sm line-clamp-1">${item.plugin_name}</div>
          <div class="mt-0.5">${this.formatCveBadge(item.cve, item.cve_list, item.cve_count)}</div>
        </td>
        <td><span class="badge-${item.severity.toLowerCase()} px-2 py-0.5 rounded text-xs font-bold">${item.severity}</span></td>
        <td class="text-xs text-slate-400 font-mono">${item.port}/${item.protocol}</td>
        <td class="text-right">
          ${item.exploit_available ? '<span class="badge-exploit px-2 py-0.5 rounded text-xs font-bold">SIM</span>' : '<span class="text-slate-500 text-xs">Não</span>'}
        </td>
      </tr>
    `).join('');

    this.refreshIcons();
  },

  // --- VULNERABILITIES EXPLORER ---
  async loadVulnerabilitiesList() {
    const tbody = document.getElementById('vuln-explorer-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-slate-400">Buscando vulnerabilidades...</td></tr>`;

    const page = this.state.vulnPage || 1;
    const pageSize = this.state.vulnPageSize || 50;

    const hostFilterVal = document.getElementById('vuln-host-filter')?.value.trim() || '';
    const isOrphan = document.getElementById('vuln-orphan-filter')?.checked || false;

    const params = {
      asset_group_id: this.state.selectedAssetGroupId || '',
      severity: document.getElementById('vuln-sev-filter')?.value || '',
      has_exploit: document.getElementById('vuln-exploit-filter')?.value || '',
      treatment_status: document.getElementById('vuln-treatment-filter')?.value || '',
      not_in_action_plan: isOrphan ? true : undefined,
      search: document.getElementById('vuln-search-input')?.value.trim() || '',
      host: hostFilterVal,
      page: page,
      page_size: pageSize
    };

    try {
      const res = await API.listVulnerabilities(params);
      let vulns = [];
      let total = 0;
      let totalPages = 1;

      if (res && res.items) {
        vulns = res.items;
        total = res.total;
        totalPages = res.total_pages;
      } else if (Array.isArray(res)) {
        vulns = res;
        total = vulns.length;
        totalPages = 1;
      }

      this.state.currentVisibleVulns = vulns;
      this.state.vulnTotalCount = total;
      this.state.vulnTotalPages = totalPages;

      const countEl = document.getElementById('vuln-explorer-count');
      if (countEl) countEl.textContent = `${total.toLocaleString()} Resultados`;

      // Update Pagination Bar
      const startIdx = total === 0 ? 0 : (page - 1) * pageSize;
      const endIdx = Math.min(startIdx + pageSize, total);
      const pageInfoEl = document.getElementById('vuln-page-info');
      const pageTotalEl = document.getElementById('vuln-page-total');
      const currPageEl = document.getElementById('vuln-current-page');
      const prevBtn = document.getElementById('vuln-prev-btn');
      const nextBtn = document.getElementById('vuln-next-btn');
      const firstBtn = document.getElementById('vuln-first-btn');
      const lastBtn = document.getElementById('vuln-last-btn');

      if (pageInfoEl) pageInfoEl.textContent = total === 0 ? '0' : `${(startIdx + 1).toLocaleString()} - ${endIdx.toLocaleString()}`;
      if (pageTotalEl) pageTotalEl.textContent = total.toLocaleString();
      if (currPageEl) currPageEl.textContent = `${page} / ${totalPages}`;
      if (prevBtn) prevBtn.disabled = page <= 1;
      if (firstBtn) firstBtn.disabled = page <= 1;
      if (nextBtn) nextBtn.disabled = page >= totalPages;
      if (lastBtn) lastBtn.disabled = page >= totalPages;

      if (!vulns || vulns.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-slate-500">Nenhuma vulnerabilidade encontrada com os filtros aplicados.</td></tr>`;
        this.updateBulkBar();
        return;
      }

      const isAuditor = (this.state.user?.role || '').toLowerCase() === 'auditor';

      tbody.innerHTML = vulns.map(v => `
        <tr class="hover:bg-slate-800/40 transition ${this.state.selectedVulnIds.has(v.id) ? 'bg-cyan-950/20' : ''}">
          <td class="text-center">
            ${isAuditor 
              ? `<span title="Modo Auditoria: Somente Leitura"><i data-lucide="eye" class="w-3.5 h-3.5 inline text-slate-500"></i></span>`
              : `<input type="checkbox" class="vuln-row-chk rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-cyan-500 cursor-pointer" value="${v.id}" ${this.state.selectedVulnIds.has(v.id) ? 'checked' : ''} onchange="App.handleVulnSelect(${v.id}, this.checked)">`
            }
          </td>
          <td>
            <span class="badge-${v.severity.toLowerCase()} px-2 py-0.5 rounded text-xs font-bold">${v.severity}</span>
          </td>
          <td>
            <button type="button" onclick="App.setHostFilter('${v.host_ip}')" class="text-left font-semibold text-sky-400 hover:text-cyan-300 font-mono text-xs hover:underline inline-flex items-center gap-1 group cursor-pointer" title="Filtrar somente vulnerabilidades deste Host/IP (${v.host_ip})">
              <span>${v.host_ip}</span>
              <i data-lucide="filter" class="w-3 h-3 opacity-0 group-hover:opacity-100 transition text-cyan-400"></i>
            </button>
            <div class="text-xs text-slate-400">${v.host_name || ''}</div>
          </td>
          <td>
            <div class="font-medium text-slate-200 line-clamp-1">${v.plugin_name}</div>
            <div class="mt-0.5">${this.formatCveBadge(v.cve, v.cve_list, v.cve_count)}</div>
          </td>
          <td class="text-xs font-mono text-slate-300">${v.port}/${v.protocol}</td>
          <td class="text-center">
            <span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30" title="Primeira detecção: ${v.first_found ? new Date(v.first_found).toLocaleDateString('pt-BR') : '-'}">${v.aging_days || 0}d</span>
          </td>
          <td class="text-center">
            ${v.exploit_available ? '<span class="badge-exploit px-2 py-0.5 rounded text-xs font-bold">SIM</span>' : '<span class="text-slate-500 text-xs">Não</span>'}
          </td>
          <td>
            <div class="flex flex-col space-y-0.5">
              <span class="px-2 py-0.5 rounded text-xs font-semibold w-fit ${this.getTreatmentStatusBadgeClass(v.treatment_status)}">${v.treatment_status}</span>
              <span class="text-[10px] text-slate-400 flex items-center">
                <i data-lucide="user" class="inline w-3 h-3 text-sky-400 mr-1"></i>
                ${v.treated_by_username ? v.treated_by_username : 'Não tratado'}
              </span>
            </div>
          </td>
          <td class="text-right">
            ${isAuditor
              ? `<button onclick="App.openVulnDetailsModal(${v.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 cursor-pointer flex items-center space-x-1 ml-auto"><i data-lucide="eye" class="w-3 h-3"></i><span>Auditar / Detalhes</span></button>`
              : `<button onclick="App.openVulnDetailsModal(${v.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 hover:bg-sky-500/20 cursor-pointer">Tratativa / Detalhes</button>`
            }
          </td>
        </tr>
      `).join('');

      // Update Header Master Checkbox
      const allChk = document.getElementById('vuln-select-all-chk');
      if (allChk) {
        if (isAuditor) {
          allChk.classList.add('hidden');
          allChk.disabled = true;
        } else {
          allChk.classList.remove('hidden');
          allChk.disabled = false;
          allChk.checked = vulns.length > 0 && vulns.every(v => this.state.selectedVulnIds.has(v.id));
        }
      }

      this.updateBulkBar();
      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-rose-400">Erro: ${e.message}</td></tr>`;
    }
  },

  handleVulnPageChange(delta) {
    const totalPages = this.state.vulnTotalPages || 1;
    const current = this.state.vulnPage || 1;
    const next = Math.max(1, Math.min(totalPages, current + delta));
    if (next !== current) {
      this.state.vulnPage = next;
      this.loadVulnerabilitiesList();
    }
  },

  handleVulnPageJump(target) {
    const totalPages = this.state.vulnTotalPages || 1;
    const targetPage = target === 'last' ? totalPages : Math.max(1, Math.min(totalPages, parseInt(target, 10) || 1));
    if (this.state.vulnPage !== targetPage) {
      this.state.vulnPage = targetPage;
      this.loadVulnerabilitiesList();
    }
  },

  handleSelectAllVulns(isChecked) {
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') return;
    if (!this.state.currentVisibleVulns) return;
    this.state.currentVisibleVulns.forEach(v => {
      if (isChecked) {
        this.state.selectedVulnIds.add(v.id);
      } else {
        this.state.selectedVulnIds.delete(v.id);
      }
    });

    document.querySelectorAll('.vuln-row-chk').forEach(c => {
      c.checked = isChecked;
    });

    this.updateBulkBar();
  },

  handleVulnSelect(vulnId, isChecked) {
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') return;
    if (isChecked) {
      this.state.selectedVulnIds.add(vulnId);
    } else {
      this.state.selectedVulnIds.delete(vulnId);
    }

    const allChk = document.getElementById('vuln-select-all-chk');
    if (allChk && this.state.currentVisibleVulns) {
      allChk.checked = this.state.currentVisibleVulns.length > 0 && this.state.currentVisibleVulns.every(v => this.state.selectedVulnIds.has(v.id));
    }

    this.updateBulkBar();
  },

  clearVulnSelection() {
    this.state.selectedVulnIds.clear();
    document.querySelectorAll('.vuln-row-chk').forEach(c => c.checked = false);
    const allChk = document.getElementById('vuln-select-all-chk');
    if (allChk) allChk.checked = false;
    this.updateBulkBar();
  },

  async loadUniqueHostsDatalist() {
    const datalist = document.getElementById('vuln-hosts-datalist');
    if (!datalist) return;
    try {
      const hosts = await API.getUniqueHosts(this.state.selectedAssetGroupId || '');
      if (Array.isArray(hosts)) {
        datalist.innerHTML = hosts.map(h => {
          const label = h.hostname ? `${h.ip} (${h.hostname})` : h.ip;
          return `<option value="${h.ip}">${label}</option>`;
        }).join('');
      }
    } catch (e) {
      console.warn('Falha ao carregar lista de hosts únicos:', e);
    }
  },

  setHostFilter(host) {
    const filterInput = document.getElementById('vuln-host-filter');
    if (filterInput) filterInput.value = host;
    this.state.vulnPage = 1;
    this.loadVulnerabilitiesList();
  },

  clearAllVulnFilters() {
    const searchInput = document.getElementById('vuln-search-input');
    const hostFilter = document.getElementById('vuln-host-filter');
    const sevFilter = document.getElementById('vuln-sev-filter');
    const exploitFilter = document.getElementById('vuln-exploit-filter');
    const treatFilter = document.getElementById('vuln-treatment-filter');
    const orphanFilter = document.getElementById('vuln-orphan-filter');

    if (searchInput) searchInput.value = '';
    if (hostFilter) hostFilter.value = '';
    if (sevFilter) sevFilter.value = '';
    if (exploitFilter) exploitFilter.value = '';
    if (treatFilter) treatFilter.value = '';
    if (orphanFilter) orphanFilter.checked = false;

    this.state.vulnPage = 1;
    this.loadVulnerabilitiesList();
  },

  clearHostFilter() {
    this.clearAllVulnFilters();
  },

  updateBulkBar() {
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') {
      const bar = document.getElementById('vuln-bulk-bar');
      if (bar) bar.classList.add('hidden');
      return;
    }
    const bar = document.getElementById('vuln-bulk-bar');
    const count = this.state.selectedVulnIds.size;
    const countEl = document.getElementById('vuln-bulk-selected-count');
    if (countEl) countEl.textContent = count;
    if (bar) {
      if (count > 0) {
        bar.classList.remove('hidden');
      } else {
        bar.classList.add('hidden');
      }
    }
    this.refreshIcons();
  },

  openBulkTreatmentModal() {
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') {
      alert('Acesso negado: auditores possuem acesso somente leitura e não podem alterar status de tratamento.');
      return;
    }
    const count = this.state.selectedVulnIds.size;
    if (count === 0) return;
    const countEl = document.getElementById('modal-bulk-count');
    if (countEl) countEl.textContent = count;
    const notesEl = document.getElementById('bulk-treatment-notes');
    if (notesEl) notesEl.value = '';
    const errEl = document.getElementById('bulk-treatment-error');
    if (errEl) errEl.classList.add('hidden');
    const modal = document.getElementById('bulk-treatment-modal');
    if (modal) modal.classList.remove('hidden');
    this.refreshIcons();
  },

  closeBulkTreatmentModal() {
    const modal = document.getElementById('bulk-treatment-modal');
    if (modal) modal.classList.add('hidden');
  },

  async handleSaveBulkTreatment(e) {
    if (e && e.preventDefault) e.preventDefault();
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') {
      alert('Acesso negado: auditores possuem acesso somente leitura e não podem alterar status de tratamento.');
      return;
    }
    const ids = Array.from(this.state.selectedVulnIds);
    if (ids.length === 0) return;

    const status = document.getElementById('bulk-treatment-status')?.value || 'In_Remediation';
    const notesEl = document.getElementById('bulk-treatment-notes');
    const notes = notesEl ? notesEl.value.trim() : '';
    const btn = document.getElementById('btn-submit-bulk-treatment');
    const errEl = document.getElementById('bulk-treatment-error');
    const notesErrEl = document.getElementById('bulk-treatment-notes-error');

    if (errEl) errEl.classList.add('hidden');
    if (notesErrEl) notesErrEl.classList.add('hidden');
    if (notesEl) notesEl.classList.remove('border-rose-400');

    // Valida nota obrigatória
    if (!notes) {
      if (notesErrEl) notesErrEl.classList.remove('hidden');
      if (notesEl) {
        notesEl.classList.add('border-rose-400');
        notesEl.focus();
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerText = 'Salvando Tratamento em Lote...';
    }

    try {
      const res = await API.bulkUpdateVulnerabilityTreatment(ids, status, notes);
      this.closeBulkTreatmentModal();
      this.clearVulnSelection();
      await this.loadVulnerabilitiesList();
      if (this.state.currentTab === 'dashboard') {
        this.loadDashboardData();
      }
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Erro ao salvar tratamento em lote.';
        errEl.classList.remove('hidden');
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = 'Confirmar Tratamento em Massa';
      }
    }
  },

  getTreatmentStatusBadgeClass(status) {
    switch (status) {
      case 'Remediated': return 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
      case 'In_Remediation': return 'bg-amber-500/20 text-amber-300 border border-amber-500/40';
      case 'In_Action_Plan': return 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40';
      case 'Accepted_Risk': return 'bg-purple-500/20 text-purple-300 border border-purple-500/40';
      default: return 'bg-rose-500/20 text-rose-300 border border-rose-500/40';
    }
  },

  // --- SCANS IMPORT & HISTORY MODULE ---
  async loadScansTable() {
    const tbody = document.getElementById('scans-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-400">Carregando histórico de scans...</td></tr>`;

    try {
      const scans = await API.listScans(this.state.selectedAssetGroupId || null);
      this.state.scansList = scans || [];

      if (!scans || scans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-500">Nenhum scan importado para o grupo selecionado.</td></tr>`;
        return;
      }

      const isAdmin = this.state.user && this.state.user.role === 'admin';

      tbody.innerHTML = scans.map(s => `
        <tr class="hover:bg-slate-800/40 transition">
          <td>
            <div class="font-semibold text-slate-200">${s.scan_name}</div>
            <div class="text-[11px] text-slate-400 font-mono">${s.filename} (${(s.file_size_bytes / 1024).toFixed(1)} KB)</div>
          </td>
          <td>
            <span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-cyan-300 font-medium border border-slate-700">${s.asset_group_name || '-'}</span>
          </td>
          <td class="text-center font-mono font-bold text-slate-200">${s.total_hosts}</td>
          <td class="text-center font-mono font-bold text-slate-200">${s.total_findings}</td>
          <td>
            <div class="flex items-center space-x-1.5 text-xs font-mono font-bold">
              <span class="text-red-400" title="Críticas">${s.critical_count}C</span>
              <span class="text-slate-600">•</span>
              <span class="text-orange-400" title="Altas">${s.high_count}A</span>
              <span class="text-slate-600">•</span>
              <span class="text-yellow-400" title="Médias">${s.medium_count}M</span>
              <span class="text-slate-600">•</span>
              <span class="text-sky-400" title="Baixas">${s.low_count}B</span>
            </div>
          </td>
          <td class="text-xs text-slate-300 font-mono">${this.formatDateBR(s.scan_date)}</td>
          <td class="text-xs text-slate-400 font-mono">${s.created_at ? new Date(s.created_at).toLocaleString('pt-BR') : '-'}</td>
          <td class="text-right space-x-1">
            ${isAdmin ? `<button onclick="App.handleDeleteScan(${s.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 cursor-pointer" title="Excluir Scan">Excluir</button>` : `<span class="text-xs text-slate-500 italic">Somente Leitura</span>`}
          </td>
        </tr>
      `).join('');

      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-rose-400">Erro: ${e.message}</td></tr>`;
    }
  },

  async handleScanUpload(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (this.state.user?.role === 'auditor') {
      alert('Auditores ISO possuem permissão apenas de leitura e não podem importar scans.');
      return;
    }
    const fileInput = document.getElementById('scan-file-input');
    const groupSelect = document.getElementById('scan-asset-group-select');
    const nameInput = document.getElementById('scan-name-input');
    const dateInput = document.getElementById('scan-date-input');
    const notesInput = document.getElementById('scan-notes-input');
    const statusMsg = document.getElementById('upload-status-msg');
    const submitBtn = document.getElementById('btn-upload-scan');

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
      alert('Selecione um arquivo CSV para importar.');
      return;
    }

    if (!groupSelect || !groupSelect.value) {
      alert('Selecione um Grupo de Ativos de destino.');
      return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('asset_group_id', groupSelect.value);
    formData.append('scan_name', nameInput.value || fileInput.files[0].name);
    formData.append('scan_type', 'baseline');
    if (dateInput && dateInput.value) {
      formData.append('scan_date', dateInput.value);
    }
    if (notesInput && notesInput.value) {
      formData.append('notes', notesInput.value);
    }

    try {
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i><span>Importando e Processando...</span>';
      }
      this.refreshIcons();

      await API.uploadScan(formData);

      if (statusMsg) {
        statusMsg.className = 'mt-4 p-3 rounded-lg text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 block';
        statusMsg.textContent = 'Scan importado e processado com sucesso!';
      }

      // Reset form fields
      fileInput.value = '';
      nameInput.value = '';
      if (dateInput) dateInput.value = '';
      if (notesInput) notesInput.value = '';

      await this.loadScansTable();
      this.loadDashboardData();
      this.loadUniqueHostsDatalist();
    } catch (err) {
      if (statusMsg) {
        statusMsg.className = 'mt-4 p-3 rounded-lg text-xs font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/40 block';
        statusMsg.textContent = `Erro na importação: ${err.message}`;
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i data-lucide="upload" class="w-4 h-4"></i><span>Importar Scan Nessus</span>';
      }
      this.refreshIcons();
    }
  },

  async handleDeleteScan(scanId) {
    if (this.state.user?.role !== 'admin') {
      alert('Apenas Administradores Gerais podem excluir scans.');
      return;
    }
    if (!confirm('Deseja realmente excluir este scan e todos os apontamentos associados?')) return;
    try {
      await API.deleteScan(scanId);
      await this.loadScansTable();
      this.loadDashboardData();
      this.loadUniqueHostsDatalist();
    } catch (e) {
      alert(`Erro ao excluir scan: ${e.message}`);
    }
  },

  downloadSampleNessusCsv() {
    const sample = `"Plugin ID";"CVE";"CVSS v3.0 Base Score";"Risk";"Host";"Protocol";"Port";"Name";"Synopsis";"Description";"Solution";"See Also";"Plugin Output";"Exploit?";"Exploit Frameworks";"Exploited by Malware?";"VPR Score";"Patch Publication Date";"First Found";"Last Found"
"104743";"CVE-2017-0144";"8.1";"Critical";"192.168.1.10";"TCP";"445";"MS17-010: Security Update for Microsoft Windows SMB Server";"The remote Windows host is affected by multiple vulnerabilities.";"A remote code execution vulnerability exists in Microsoft Server Message Block 1.0 (SMBv1).";"Microsoft has released a set of patches for Windows Vista, 2008, 7, 2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.";"https://technet.microsoft.com/en-us/library/security/ms17-010.aspx";"Vulnerable Windows SMB Server detected";"true";"Metasploit,CANVAS,Core Impact";"true";"9.8";"2017-03-14";"10/01/2026 09:00:00";"03/09/2026 10:00:00"
"58453";"CVE-2012-1823";"7.5";"High";"192.168.1.20";"TCP";"80";"PHP CGI Argument Injection Remote Code Execution";"The remote web server is running a version of PHP that is affected by a remote code execution vulnerability.";"The PHP CGI component allows command line arguments to be passed as query strings.";"Upgrade to PHP 5.3.12 / 5.4.2 or later.";"https://bugs.php.net/bug.php?id=61807";"PHP 5.3.10 detected";"true";"Metasploit";"false";"7.9";"2012-05-03";"15/02/2026 14:00:00";"03/09/2026 10:00:00"
`;
    const blob = new Blob([sample], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', 'modelo_nessus_exemplo.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  },

  // --- USERS MANAGEMENT (ADMIN ONLY) ---
  // --- USERS MANAGEMENT (ADMIN ONLY) ---
  async loadUsersTable() {
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-slate-400">Carregando usuários...</td></tr>`;

    try {
      const users = await API.listUsers();
      this.state.usersList = users || [];

      tbody.innerHTML = this.state.usersList.map(u => {
        let roleBadge = '<span class="px-2.5 py-1 rounded text-xs font-bold bg-slate-800 text-slate-300 border border-slate-700">DESCONHECIDO</span>';
        if (u.role === 'admin') {
          roleBadge = '<span class="px-2.5 py-1 rounded text-xs font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">ADMINISTRADOR GERAL</span>';
        } else if (u.role === 'analyst') {
          roleBadge = '<span class="px-2.5 py-1 rounded text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">ANALISTA DE SEGURANÇA</span>';
        } else if (u.role === 'auditor') {
          roleBadge = '<span class="px-2.5 py-1 rounded text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">AUDITOR ISO</span>';
        }

        const isLdap = u.auth_type === 'ldap';
        const originBadge = isLdap
          ? `<div class="space-y-0.5">
               <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40 inline-flex items-center space-x-1">
                 <i data-lucide="network" class="w-3 h-3"></i>
                 <span>LDAP (AD)</span>
               </span>
               <div class="text-[10px] text-purple-400 font-mono">${u.sam_account_name || u.username}</div>
             </div>`
          : `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-300 border border-slate-700 inline-flex items-center space-x-1">
               <i data-lucide="user" class="w-3 h-3"></i>
               <span>Local</span>
             </span>`;

        let groupsScopeBadge = '';
        if (u.role === 'admin') {
          groupsScopeBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">Acesso Total (Todos)</span>';
        } else if (u.allowed_groups && u.allowed_groups.length > 0) {
          groupsScopeBadge = `<div class="flex flex-wrap gap-1 max-w-xs">` + u.allowed_groups.map(g => {
            return `<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-teal-300 border border-slate-700" title="${g.asset_group_name || 'Grupo'} (Acesso concedido + herança para todos os subgrupos)">
              <span class="font-medium">🏢 ${g.asset_group_name || `Grupo #${g.asset_group_id}`}</span>
            </span>`;
          }).join('') + `</div>`;
        } else {
          groupsScopeBadge = '<span class="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-400 border border-slate-700">Global (Sem restrições)</span>';
        }

        return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="font-semibold text-slate-200">${u.username}</td>
          <td>${originBadge}</td>
          <td class="text-slate-300">${u.full_name || '-'}</td>
          <td class="text-slate-400 font-mono text-xs">${u.email}</td>
          <td>${roleBadge}</td>
          <td>${groupsScopeBadge}</td>
          <td class="text-center">
            ${u.is_active ? '<span class="text-emerald-400 font-semibold text-xs">Ativo</span>' : '<span class="text-rose-400 font-semibold text-xs">Inativo</span>'}
          </td>
          <td class="text-xs text-slate-400 font-mono">${new Date(u.created_at).toLocaleDateString('pt-BR')}</td>
          <td class="text-right space-x-1">
            <button onclick="App.openEditUserModal(${u.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700 cursor-pointer">Editar</button>
            ${u.username !== 'Admin' ? `<button onclick="App.handleDeleteUser(${u.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 cursor-pointer">Excluir</button>` : ''}
          </td>
        </tr>
      `;
      }).join('');
      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-6 text-rose-400">Erro: ${e.message}</td></tr>`;
    }
  },

  async renderUserModalGroups(userAllowedGroups = []) {
    const listEl = document.getElementById('user-modal-groups-list');
    if (!listEl) return;

    let groups = this.state.assetGroups || [];
    if (!groups.length) {
      try {
        groups = await API.listAssetGroups();
        this.state.assetGroups = groups || [];
      } catch (e) {
        console.warn('Erro ao carregar grupos para modal:', e);
      }
    }

    if (!groups.length) {
      listEl.innerHTML = '<div class="text-center py-4 text-xs text-slate-400">Nenhum grupo de ativos cadastrado no sistema.</div>';
      return;
    }

    const permsMap = {};
    (userAllowedGroups || []).forEach(p => {
      permsMap[p.asset_group_id] = p;
    });

    const hierarchical = this.buildHierarchicalGroupList(groups);

    listEl.innerHTML = hierarchical.map(g => {
      const isChecked = !!permsMap[g.id];
      const depth = g.depth || 1;
      const lvl = g.level || depth;
      const descendants = this.getGroupDescendantIds(g.id, groups);
      const hasSubgroups = descendants.length > 0;

      let badge = '';
      let borderIndent = '';
      let icon = '';

      if (depth === 1) {
        icon = '🏢';
        badge = hasSubgroups
          ? `<span class="text-[10px] px-2 py-0.5 rounded bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-400 font-medium">Nível 1 - Corporativo (${descendants.length} subgrupos subordinados)</span>`
          : `<span class="text-[10px] px-2 py-0.5 rounded bg-teal-50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-400 font-medium">Nível 1 - Grupo Raiz</span>`;
      } else if (depth === 2) {
        icon = '📍';
        borderIndent = 'margin-left: 1.25rem; border-left: 2px solid #0d9488;';
        badge = hasSubgroups
          ? `<span class="text-[10px] px-2 py-0.5 rounded bg-teal-50 dark:bg-teal-950/40 text-teal-700 dark:text-teal-400 font-medium">📍 Nível 2 - Subgrupo (${descendants.length} subordinados)</span>`
          : `<span class="text-[10px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-medium">📍 Nível 2 - Subgrupo</span>`;
      } else {
        icon = '⤷';
        const leftIndent = Math.min((depth - 1) * 1.25, 3.75);
        borderIndent = `margin-left: ${leftIndent}rem; border-left: 2px solid #d97706;`;
        badge = `<span class="text-[10px] px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 font-medium">⤷ Nível ${lvl} - Sub-subgrupo</span>`;
      }

      return `
        <label for="user-grp-check-${g.id}" style="${borderIndent}" class="p-2.5 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/90 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition flex items-center justify-between cursor-pointer group">
          <div class="flex items-center space-x-2.5">
            <input type="checkbox" id="user-grp-check-${g.id}" value="${g.id}" ${isChecked ? 'checked' : ''} class="user-grp-master rounded bg-white dark:bg-slate-900 border-slate-300 dark:border-slate-700 text-teal-600 focus:ring-teal-500 cursor-pointer">
            <span class="text-xs font-semibold text-slate-800 dark:text-slate-200 group-hover:text-teal-700 dark:group-hover:text-teal-400 transition flex items-center space-x-1.5">
              <span>${icon} ${g.name}</span>
              ${g.hierarchy_path ? `<span class="text-[10px] text-slate-400 font-normal">(${g.hierarchy_path})</span>` : (g.parent_name ? `<span class="text-[10px] text-slate-400 font-normal">(${g.parent_name})</span>` : '')}
            </span>
          </div>
          ${badge}
        </label>
      `;
    }).join('');
  },

  toggleAllGroupCheckboxes(check) {
    document.querySelectorAll('.user-grp-master').forEach(cb => {
      cb.checked = check;
    });
  },

  onUserRoleChange() {
    const roleSelect = document.getElementById('user-modal-role');
    const adminNotice = document.getElementById('user-modal-admin-notice');
    const groupsContainer = document.getElementById('user-modal-groups-container');
    if (!roleSelect) return;
    const role = roleSelect.value;
    if (role === 'admin') {
      adminNotice?.classList.remove('hidden');
      groupsContainer?.classList.add('hidden');
    } else {
      adminNotice?.classList.add('hidden');
      groupsContainer?.classList.remove('hidden');
    }
  },

  openCreateUserModal() {
    document.getElementById('user-modal-title').innerHTML = `
      <i data-lucide="user-plus" class="w-4 h-4 text-blue-400"></i>
      <span>Novo Usuário</span>
    `;
    document.getElementById('user-modal-id').value = '';
    document.getElementById('user-modal-username').value = '';
    document.getElementById('user-modal-username').disabled = false;
    document.getElementById('user-modal-email').value = '';
    document.getElementById('user-modal-fullname').value = '';
    document.getElementById('user-modal-password').value = '';
    document.getElementById('user-modal-sam').value = '';
    document.getElementById('user-modal-role').value = 'analyst';
    document.getElementById('user-modal-active').checked = true;

    // Show account type selection
    const typeGroup = document.getElementById('user-modal-type-group');
    if (typeGroup) typeGroup.classList.remove('hidden');

    const radioLocal = document.getElementById('modal-auth-type-local');
    if (radioLocal) radioLocal.checked = true;

    this.onUserAuthTypeChange('local', false);
    this.onUserRoleChange();
    this.renderUserModalGroups([]);

    document.getElementById('user-modal').classList.remove('hidden');
    this.refreshIcons();
  },

  openEditUserModal(userId) {
    const user = this.state.usersList.find(u => u.id === userId);
    if (!user) return;

    const isLdap = user.auth_type === 'ldap';

    document.getElementById('user-modal-title').innerHTML = `
      <i data-lucide="user-cog" class="w-4 h-4 text-sky-400"></i>
      <span>Editar Usuário: ${user.username}</span>
    `;
    document.getElementById('user-modal-id').value = user.id;
    document.getElementById('user-modal-username').value = user.username;
    document.getElementById('user-modal-username').disabled = true;
    document.getElementById('user-modal-email').value = user.email;
    document.getElementById('user-modal-fullname').value = user.full_name || '';
    document.getElementById('user-modal-password').value = '';
    document.getElementById('user-modal-sam').value = user.sam_account_name || user.username;
    document.getElementById('user-modal-role').value = user.role;
    document.getElementById('user-modal-active').checked = user.is_active;

    // Lock account type in edit mode
    const typeGroup = document.getElementById('user-modal-type-group');
    if (typeGroup) typeGroup.classList.add('hidden');

    this.onUserAuthTypeChange(isLdap ? 'ldap' : 'local', true);
    this.onUserRoleChange();
    this.renderUserModalGroups(user.allowed_groups || []);

    document.getElementById('user-modal').classList.remove('hidden');
    this.refreshIcons();
  },

  onUserAuthTypeChange(authType, isEdit = false) {
    const isLdap = authType === 'ldap';
    const ldapBox = document.getElementById('user-ldap-box');
    const pwdContainer = document.getElementById('user-modal-pwd-container');
    const pwdNotice = document.getElementById('user-modal-ldap-pwd-notice');
    const pwdInput = document.getElementById('user-modal-password');
    const pwdLabel = document.getElementById('user-modal-password-label');
    const feedback = document.getElementById('user-ldap-feedback');

    if (feedback) {
      feedback.className = 'hidden';
      feedback.innerHTML = '';
    }

    if (isLdap) {
      if (ldapBox) {
        if (!isEdit) ldapBox.classList.remove('hidden');
        else ldapBox.classList.add('hidden');
      }
      if (pwdContainer) pwdContainer.classList.add('hidden');
      if (pwdNotice) pwdNotice.classList.remove('hidden');
      if (pwdInput) {
        pwdInput.required = false;
        pwdInput.value = '';
      }
    } else {
      if (ldapBox) ldapBox.classList.add('hidden');
      if (pwdContainer) pwdContainer.classList.remove('hidden');
      if (pwdNotice) pwdNotice.classList.add('hidden');
      if (pwdInput) {
        pwdInput.required = !isEdit;
      }
      if (pwdLabel) {
        pwdLabel.textContent = isEdit ? 'Nova Senha (deixe em branco para manter)' : 'Senha *';
      }
    }

    this.refreshIcons();
  },

  async handleValidateSamAccountName() {
    const samInput = document.getElementById('user-modal-sam');
    const feedback = document.getElementById('user-ldap-feedback');
    const btnText = document.getElementById('btn-validate-sam-text');
    const sam = samInput ? samInput.value.trim() : '';

    if (!sam) {
      if (feedback) {
        feedback.className = 'p-2.5 rounded-lg border bg-rose-500/10 border-rose-500/30 text-rose-300 text-xs flex items-center space-x-1.5';
        feedback.innerHTML = '<i data-lucide="alert-circle" class="w-4 h-4"></i><span>Informe o sAMAccountName para validar no Active Directory.</span>';
        this.refreshIcons();
      }
      return;
    }

    if (btnText) btnText.textContent = 'Consultando...';
    if (feedback) feedback.className = 'hidden';

    try {
      const data = await API.validateLdapUser(sam);

      // Auto-populate form fields
      document.getElementById('user-modal-username').value = data.sam_account_name;
      if (data.full_name) {
        document.getElementById('user-modal-fullname').value = data.full_name;
      }
      if (data.email) {
        document.getElementById('user-modal-email').value = data.email;
      }

      if (feedback) {
        feedback.className = 'p-2.5 rounded-lg border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 text-xs flex items-center space-x-2';
        feedback.innerHTML = `
          <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400 flex-shrink-0"></i>
          <div>
            <strong>Usuário validado no Active Directory:</strong>
            <span class="text-white">${data.full_name || data.sam_account_name}</span> 
            <span class="text-slate-400 font-mono text-[10px]">(${data.email || 'sem e-mail'})</span>
          </div>
        `;
        this.refreshIcons();
      }
    } catch (err) {
      if (feedback) {
        feedback.className = 'p-2.5 rounded-lg border bg-rose-500/10 border-rose-500/30 text-rose-300 text-xs flex items-center space-x-2';
        feedback.innerHTML = `
          <i data-lucide="alert-triangle" class="w-4 h-4 text-rose-400 flex-shrink-0"></i>
          <div>${err.message || 'Usuário não localizado no Active Directory.'}</div>
        `;
        this.refreshIcons();
      }
    } finally {
      if (btnText) btnText.textContent = 'Validar no LDAP';
      this.refreshIcons();
    }
  },

  closeUserModal() {
    document.getElementById('user-modal')?.classList.add('hidden');
  },

  async handleSaveUser(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (this.state.user?.role !== 'admin') {
      alert('Apenas Administradores Gerais podem gerenciar usuários.');
      return;
    }
    if (this._isSavingUser) return;
    this._isSavingUser = true;

    const submitBtn = document.getElementById('btn-save-user-submit');
    const originalText = submitBtn ? submitBtn.innerHTML : 'Salvar Usuário';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span>Salvando...</span>';
    }

    const id = document.getElementById('user-modal-id').value;
    const password = document.getElementById('user-modal-password').value;
    const isLdapSelected = document.getElementById('modal-auth-type-ldap')?.checked;
    const role = document.getElementById('user-modal-role').value;

    let allowed_groups = null;
    if (role !== 'admin') {
      allowed_groups = [];
      document.querySelectorAll('.user-grp-master').forEach(cb => {
        if (cb.checked) {
          const gid = parseInt(cb.value);
          allowed_groups.push({
            asset_group_id: gid,
            can_treat: true,
            can_import: true,
            can_author: true
          });
        }
      });
    }

    try {
      if (id) {
        const updateData = {
          email: document.getElementById('user-modal-email').value.trim(),
          full_name: document.getElementById('user-modal-fullname').value.trim(),
          role: role,
          is_active: document.getElementById('user-modal-active').checked,
          allowed_groups: allowed_groups
        };
        if (password) updateData.password = password;
        await API.updateUser(id, updateData);
      } else {
        const authType = isLdapSelected ? 'ldap' : 'local';
        const createData = {
          username: document.getElementById('user-modal-username').value.trim(),
          email: document.getElementById('user-modal-email').value.trim(),
          full_name: document.getElementById('user-modal-fullname').value.trim(),
          role: role,
          is_active: document.getElementById('user-modal-active').checked,
          auth_type: authType,
          allowed_groups: allowed_groups
        };

        if (authType === 'ldap') {
          const sam = document.getElementById('user-modal-sam').value.trim();
          createData.sam_account_name = sam || createData.username;
          if (!createData.username) createData.username = createData.sam_account_name;
        } else {
          createData.password = password;
        }

        await API.createUser(createData);
      }
      this.closeUserModal();
      this.loadUsersTable();
    } catch (e) {
      alert(`Erro ao salvar usuário: ${e.message}`);
    } finally {
      this._isSavingUser = false;
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
        this.refreshIcons();
      }
    }
  },

  async handleDeleteUser(userId) {
    if (this.state.user?.role !== 'admin') {
      alert('Apenas Administradores Gerais podem gerenciar usuários.');
      return;
    }
    if (!confirm('Deseja realmente excluir este usuário?')) return;
    try {
      await API.deleteUser(userId);
      this.loadUsersTable();
    } catch (e) {
      alert(`Erro ao excluir usuário: ${e.message}`);
    }
  },

  // --- LDAP CONFIGURATION CONTROLLER (ADMIN ONLY) ---
  async loadLdapConfig() {
    const statusBadge = document.getElementById('ldap-badge-status');
    if (statusBadge) {
      statusBadge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700 flex items-center space-x-1.5';
      statusBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-500 animate-pulse"></span><span>Carregando...</span>';
    }

    try {
      const cfg = await API.getLdapConfig();
      this.state.ldapConfig = cfg;

      // Populate Inputs
      const toggle = document.getElementById('ldap-enabled-toggle');
      if (toggle) toggle.checked = !!cfg.is_enabled;

      const hostInput = document.getElementById('ldap-server-host');
      if (hostInput) hostInput.value = cfg.server_host || '';

      const portInput = document.getElementById('ldap-server-port');
      if (portInput) portInput.value = cfg.server_port || 389;

      const timeoutInput = document.getElementById('ldap-timeout');
      if (timeoutInput) timeoutInput.value = cfg.connection_timeout || 5;

      const bindUserInput = document.getElementById('ldap-bind-user');
      if (bindUserInput) bindUserInput.value = cfg.bind_user || '';

      const baseDnInput = document.getElementById('ldap-base-dn');
      if (baseDnInput) baseDnInput.value = cfg.base_dn || '';

      const filterInput = document.getElementById('ldap-user-filter');
      if (filterInput) filterInput.value = cfg.user_search_filter || '(&(objectClass=user)(sAMAccountName={username}))';

      const samAttrInput = document.getElementById('ldap-sam-attr');
      if (samAttrInput) samAttrInput.value = cfg.sam_attribute || 'sAMAccountName';

      const nameAttrInput = document.getElementById('ldap-name-attr');
      if (nameAttrInput) nameAttrInput.value = cfg.name_attribute || 'displayName';

      const emailAttrInput = document.getElementById('ldap-email-attr');
      if (emailAttrInput) emailAttrInput.value = cfg.email_attribute || 'mail';

      // Security radio
      if (cfg.use_ssl) {
        const radSsl = document.getElementById('ldap-sec-ssl');
        if (radSsl) radSsl.checked = true;
      } else if (cfg.use_starttls) {
        const radTls = document.getElementById('ldap-sec-starttls');
        if (radTls) radTls.checked = true;
      } else {
        const radPlain = document.getElementById('ldap-sec-plain');
        if (radPlain) radPlain.checked = true;
      }

      // Password status
      const pwdInput = document.getElementById('ldap-bind-password');
      const pwdStatus = document.getElementById('ldap-pwd-status');
      if (pwdInput) {
        pwdInput.value = '';
        if (cfg.is_password_configured) {
          pwdInput.placeholder = '•••••••• (Senha já configurada. Digite para alterar)';
          if (pwdStatus) {
            pwdStatus.textContent = '✓ Senha salva';
            pwdStatus.className = 'text-[10px] text-emerald-400 font-semibold';
          }
        } else {
          pwdInput.placeholder = 'Senha do usuário leitor';
          if (pwdStatus) {
            pwdStatus.textContent = 'Nenhuma senha configurada';
            pwdStatus.className = 'text-[10px] text-slate-500';
          }
        }
      }

      this.handleLdapToggleChange();
    } catch (e) {
      if (statusBadge) {
        statusBadge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40';
        statusBadge.textContent = 'Erro ao carregar';
      }
      console.error('Error loading LDAP config:', e);
    }
  },

  handleLdapToggleChange() {
    const toggle = document.getElementById('ldap-enabled-toggle');
    const isEnabled = toggle ? toggle.checked : false;
    const statusBadge = document.getElementById('ldap-badge-status');

    if (statusBadge) {
      if (isEnabled) {
        statusBadge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center space-x-1.5';
        statusBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span>Integração LDAP Ativa</span>';
      } else {
        statusBadge.className = 'px-3 py-1 rounded-full text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700 flex items-center space-x-1.5';
        statusBadge.innerHTML = '<span class="w-2 h-2 rounded-full bg-slate-500"></span><span>Integração LDAP Inativa</span>';
      }
    }

    // Toggle required stars visibility
    document.querySelectorAll('.ldap-req-star').forEach(el => {
      if (isEnabled) el.classList.remove('opacity-30');
      else el.classList.add('opacity-30');
    });
  },

  onLdapSecurityChange(secType) {
    const portInput = document.getElementById('ldap-server-port');
    if (!portInput) return;
    const currentPort = parseInt(portInput.value, 10);
    if (secType === 'ssl' && currentPort === 389) {
      portInput.value = 636;
    } else if ((secType === 'plain' || secType === 'starttls') && currentPort === 636) {
      portInput.value = 389;
    }
  },

  toggleLdapPwdVisibility() {
    const pwdInput = document.getElementById('ldap-bind-password');
    const pwdIcon = document.getElementById('ldap-pwd-icon');
    if (!pwdInput) return;
    if (pwdInput.type === 'password') {
      pwdInput.type = 'text';
      if (pwdIcon) pwdIcon.setAttribute('data-lucide', 'eye-off');
    } else {
      pwdInput.type = 'password';
      if (pwdIcon) pwdIcon.setAttribute('data-lucide', 'eye');
    }
    this.refreshIcons();
  },

  async handleTestLdapConnection() {
    const alertBox = document.getElementById('ldap-test-alert');
    const alertIcon = document.getElementById('ldap-test-alert-icon');
    const alertTitle = document.getElementById('ldap-test-alert-title');
    const alertDesc = document.getElementById('ldap-test-alert-desc');
    const btn = document.getElementById('btn-test-ldap');
    const btnText = document.getElementById('btn-test-ldap-text');

    const serverHost = document.getElementById('ldap-server-host')?.value.trim() || '';
    const serverPort = parseInt(document.getElementById('ldap-server-port')?.value || '389', 10);
    const bindUser = document.getElementById('ldap-bind-user')?.value.trim() || '';
    const bindPassword = document.getElementById('ldap-bind-password')?.value || '';
    const baseDn = document.getElementById('ldap-base-dn')?.value.trim() || '';
    const timeout = parseInt(document.getElementById('ldap-timeout')?.value || '5', 10);

    const isSsl = document.getElementById('ldap-sec-ssl')?.checked || false;
    const isStartTls = document.getElementById('ldap-sec-starttls')?.checked || false;

    if (!serverHost || !bindUser) {
      if (alertBox) {
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-amber-500/10 border-amber-500/30 text-amber-300 flex items-start space-x-3';
        if (alertTitle) alertTitle.textContent = 'Parâmetros incompletos';
        if (alertDesc) alertDesc.textContent = 'Informe ao menos o Servidor LDAP e o Usuário de Leitura (Bind) para testar a conectividade.';
      }
      return;
    }

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Testando conexão...';
    if (alertBox) alertBox.classList.add('hidden');

    try {
      const payload = {
        server_host: serverHost,
        server_port: serverPort,
        use_ssl: isSsl,
        use_starttls: isStartTls,
        bind_user: bindUser,
        bind_password: bindPassword || undefined,
        base_dn: baseDn || undefined,
        connection_timeout: timeout
      };

      const res = await API.testLdapConnection(payload);

      if (alertBox) {
        alertBox.classList.remove('hidden');
        if (res.success) {
          alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 flex items-start space-x-3';
          if (alertTitle) alertTitle.textContent = '✓ Conexão bem-sucedida!';
          if (alertDesc) alertDesc.textContent = res.message;
        } else {
          alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-start space-x-3';
          if (alertTitle) alertTitle.textContent = '✗ Falha na conexão LDAP/Active Directory';
          if (alertDesc) alertDesc.textContent = res.message;
        }
      }
    } catch (err) {
      if (alertBox) {
        alertBox.classList.remove('hidden');
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-start space-x-3';
        if (alertTitle) alertTitle.textContent = '✗ Erro ao testar LDAP';
        if (alertDesc) alertDesc.textContent = err.message || 'Erro inesperado ao conectar ao servidor LDAP.';
      }
    } finally {
      if (btn) btn.disabled = false;
      if (btnText) btnText.textContent = 'Testar Conexão';
      this.refreshIcons();
    }
  },

  async handleSaveLdapConfig(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (this.state.user?.role !== 'admin') {
      alert('Acesso negado: apenas Administradores Gerais podem salvar as configurações LDAP.');
      return;
    }

    const btn = document.getElementById('btn-save-ldap');
    const btnText = document.getElementById('btn-save-ldap-text');
    const alertBox = document.getElementById('ldap-test-alert');
    const alertTitle = document.getElementById('ldap-test-alert-title');
    const alertDesc = document.getElementById('ldap-test-alert-desc');

    const isEnabled = document.getElementById('ldap-enabled-toggle')?.checked || false;
    const serverHost = document.getElementById('ldap-server-host')?.value.trim() || '';
    const serverPort = parseInt(document.getElementById('ldap-server-port')?.value || '389', 10);
    const bindUser = document.getElementById('ldap-bind-user')?.value.trim() || '';
    const bindPassword = document.getElementById('ldap-bind-password')?.value || '';
    const baseDn = document.getElementById('ldap-base-dn')?.value.trim() || '';
    const timeout = parseInt(document.getElementById('ldap-timeout')?.value || '5', 10);

    const isSsl = document.getElementById('ldap-sec-ssl')?.checked || false;
    const isStartTls = document.getElementById('ldap-sec-starttls')?.checked || false;

    const userFilter = document.getElementById('ldap-user-filter')?.value.trim() || '(&(objectClass=user)(sAMAccountName={username}))';
    const samAttr = document.getElementById('ldap-sam-attr')?.value.trim() || 'sAMAccountName';
    const nameAttr = document.getElementById('ldap-name-attr')?.value.trim() || 'displayName';
    const emailAttr = document.getElementById('ldap-email-attr')?.value.trim() || 'mail';

    if (isEnabled && (!serverHost || !serverPort || !bindUser || !baseDn)) {
      alert('Ao habilitar a integração LDAP, os campos Servidor, Porta, Usuário de Leitura e Base DN são obrigatórios.');
      return;
    }

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = 'Salvando...';

    try {
      const payload = {
        is_enabled: isEnabled,
        server_host: serverHost,
        server_port: serverPort,
        use_ssl: isSsl,
        use_starttls: isStartTls,
        bind_user: bindUser,
        base_dn: baseDn,
        user_search_filter: userFilter,
        sam_attribute: samAttr,
        name_attribute: nameAttr,
        email_attribute: emailAttr,
        connection_timeout: timeout
      };

      if (bindPassword && bindPassword.trim()) {
        payload.bind_password = bindPassword.trim();
      }

      await API.updateLdapConfig(payload);

      if (alertBox) {
        alertBox.classList.remove('hidden');
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 flex items-start space-x-3';
        if (alertTitle) alertTitle.textContent = '✓ Configurações salvas com sucesso!';
        if (alertDesc) alertDesc.textContent = isEnabled
          ? 'Integração LDAP / Active Directory ativada e pronta para autenticação e cadastro de usuários.'
          : 'Integração LDAP desabilitada. O sistema funcionará exclusivamente com autenticação local.';
      }

      await this.loadLdapConfig();
      alert('Configurações salvas com sucesso!');
    } catch (err) {
      if (alertBox) {
        alertBox.classList.remove('hidden');
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-start space-x-3';
        if (alertTitle) alertTitle.textContent = '✗ Erro ao salvar configurações LDAP';
        if (alertDesc) alertDesc.textContent = err.message || 'Falha na comunicação com a API.';
      }
      alert(`Erro ao salvar configurações LDAP: ${err.message}`);
    } finally {
      if (btn) btn.disabled = false;
      if (btnText) btnText.textContent = 'Salvar Configurações';
      this.refreshIcons();
    }
  },

  // --- MODALS & DETAILS VIEW ---
  async openVulnDetailsModal(vulnId) {
    const modal = document.getElementById('vuln-detail-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    // Reset scroll position to top when opening modal
    const modalBody = modal.querySelector('.overflow-y-auto');
    if (modalBody) modalBody.scrollTop = 0;

    const titleEl = document.getElementById('modal-vuln-title');
    if (titleEl) {
      titleEl.textContent = 'Carregando vulnerabilidade...';
      titleEl.title = '';
    }

    try {
      const v = await API.getVulnerability(vulnId);
      this.state.currentVulnModalData = v;
      document.getElementById('modal-vuln-id').value = v.id;

      if (titleEl) {
        titleEl.textContent = v.plugin_name || 'Vulnerabilidade sem nome';
        titleEl.title = v.plugin_name || '';
      }

      const hostText = `${v.host_ip} (${v.host_name || 'Sem nome'})`;
      const hostEl = document.getElementById('modal-vuln-host');
      hostEl.textContent = hostText;
      hostEl.title = hostText;
      const groupEl = document.getElementById('modal-vuln-group');
      groupEl.textContent = v.asset_group_name || '-';
      groupEl.title = v.asset_group_name || '-';
      
      // Multi-CVE extraction and rendering
      let cveList = v.cve_list || [];
      if (!cveList.length && v.cve) {
        cveList = v.cve.split(/[\s,;]+/).map(s => s.trim()).filter(s => s.toUpperCase().startsWith('CVE-'));
      }
      const cveCount = v.cve_count > 0 ? v.cve_count : cveList.length;
      this.state.currentModalCVEs = cveList;

      const cveEl = document.getElementById('modal-vuln-cve');
      const cveBadgeEl = document.getElementById('modal-vuln-cve-badge');
      if (cveList.length > 0) {
        cveEl.textContent = cveList[0];
        if (cveCount > 1) {
          cveBadgeEl.textContent = `+${cveCount - 1} CVEs vinculadas`;
          cveBadgeEl.classList.remove('hidden');
        } else {
          cveBadgeEl.classList.add('hidden');
        }
      } else {
        cveEl.textContent = v.cve || 'Nenhum CVE';
        cveBadgeEl.classList.add('hidden');
      }

      // Render CVEs list section
      const cveCountEl = document.getElementById('modal-cve-count');
      const cveSection = document.getElementById('modal-cves-section');
      const cveSearchInput = document.getElementById('modal-cve-search');
      if (cveSearchInput) cveSearchInput.value = '';

      if (cveCountEl) cveCountEl.textContent = cveCount;
      if (cveSection) {
        if (cveCount === 0) {
          cveSection.classList.add('hidden');
        } else {
          cveSection.classList.remove('hidden');
        }
      }
      this.renderModalCveBadges(cveList);

      const cvssVal = v.cvss_v3 ? v.cvss_v3.toFixed(1) : (v.cvss_v2 ? v.cvss_v2.toFixed(1) : null);
      const cvssGridEl = document.getElementById('modal-vuln-cvss');
      if (cvssGridEl) cvssGridEl.textContent = cvssVal || '-';

      const cvssBadgeEl = document.getElementById('modal-vuln-cvss-badge');
      if (cvssBadgeEl) {
        cvssBadgeEl.textContent = cvssVal ? `CVSS ${cvssVal}` : 'CVSS -';
      }

      document.getElementById('modal-vuln-port').textContent = `${v.port}/${v.protocol}`;
      document.getElementById('modal-vuln-aging').textContent = `${v.aging_days || 0} dias`;
      const ffEl = document.getElementById('modal-vuln-firstfound');
      if (ffEl) {
        ffEl.textContent = v.first_found ? new Date(v.first_found).toLocaleDateString('pt-BR') : '-';
      }
      document.getElementById('modal-vuln-severity').textContent = v.severity;
      document.getElementById('modal-vuln-severity').className = `badge-${v.severity.toLowerCase()} px-2.5 py-0.5 rounded text-xs font-bold`;
      
      const exploitEl = document.getElementById('modal-vuln-exploit');
      if (exploitEl) {
        if (v.exploit_available) {
          const fw = (v.exploit_frameworks || '').split(',')[0].trim();
          const fwText = fw ? ` (${fw})` : '';
          exploitEl.innerHTML = `<i data-lucide="zap" class="w-3 h-3 text-purple-400 mr-1"></i>Exploit: SIM${fwText}`;
          exploitEl.className = 'badge-exploit px-2.5 py-0.5 rounded text-xs font-bold inline-flex items-center';
          exploitEl.title = v.exploit_frameworks ? `Frameworks: ${v.exploit_frameworks}` : 'Exploit disponível publicamente';
          exploitEl.classList.remove('hidden');
        } else {
          exploitEl.innerHTML = `<span class="opacity-75">Sem Exploit</span>`;
          exploitEl.className = 'px-2 py-0.5 rounded text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700/60 inline-flex items-center';
          exploitEl.title = 'Nenhum exploit público conhecido';
          exploitEl.classList.remove('hidden');
        }
      }

      document.getElementById('modal-vuln-synopsis').textContent = v.synopsis || 'Sem sinopse disponível.';
      document.getElementById('modal-vuln-description').textContent = v.description || 'Sem descrição.';
      document.getElementById('modal-vuln-solution').textContent = v.solution || 'Consulte a documentação do fornecedor.';
      document.getElementById('modal-vuln-seealso').textContent = v.see_also || '-';
      document.getElementById('modal-vuln-output').textContent = v.plugin_output || 'Nenhum output registrado.';

      document.getElementById('modal-treatment-status').value = v.treatment_status;
      document.getElementById('modal-treatment-notes').value = v.treatment_notes || '';

      // Auditor Mode: disable treatment controls and hide save button
      const isAuditor = (this.state.user?.role || '').toLowerCase() === 'auditor';
      const statusSelect = document.getElementById('modal-treatment-status');
      const notesInput = document.getElementById('modal-treatment-notes');
      const saveBtn = document.getElementById('btn-save-treatment');
      const auditorBadge = document.getElementById('modal-treatment-auditor-badge');

      if (statusSelect) statusSelect.disabled = isAuditor;
      if (notesInput) notesInput.disabled = isAuditor;
      if (saveBtn) {
        if (isAuditor) saveBtn.classList.add('hidden');
        else saveBtn.classList.remove('hidden');
      }
      if (auditorBadge) {
        if (isAuditor) auditorBadge.classList.remove('hidden');
        else auditorBadge.classList.add('hidden');
      }

      const auditUser = document.getElementById('modal-treatment-user');
      const auditDate = document.getElementById('modal-treatment-date');
      if (auditUser) {
        auditUser.textContent = v.treated_by_username || 'Não registrada / Aberta';
      }
      if (auditDate) {
        auditDate.textContent = v.treated_at ? new Date(v.treated_at).toLocaleString('pt-BR') : '-';
      }

      // Limpa erros e borda de erro do campo de nota
      const notesError = document.getElementById('modal-treatment-notes-error');
      const saveError = document.getElementById('modal-treatment-save-error');
      if (notesInput) notesInput.classList.remove('border-rose-400', 'focus:ring-rose-400');
      if (notesError) notesError.classList.add('hidden');
      if (saveError) saveError.classList.add('hidden');

      // Render Dedicated Action Plan Card
      this.renderVulnActionPlanCard(v);

      this.refreshIcons();

      // Carrega histórico de auditoria assincronamente
      this._loadTreatmentHistory(vulnId);

    } catch (e) {
      alert(`Erro ao carregar detalhes: ${e.message}`);
    }
  },

  renderModalCveBadges(cves) {
    const container = document.getElementById('modal-cves-list');
    if (!container) return;
    if (!cves || cves.length === 0) {
      container.innerHTML = '<span class="text-xs text-slate-500 py-1 px-2">Nenhuma CVE correspondente encontrada.</span>';
      return;
    }
    container.innerHTML = cves.map(cve => `
      <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener noreferrer" 
         class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono bg-sky-950/80 text-sky-300 border border-sky-800/70 hover:bg-sky-900 hover:text-white transition shadow-sm" 
         title="Abrir detalhes oficiais da ${cve} no NIST NVD">
        <span>${cve}</span>
        <i data-lucide="external-link" class="w-2.5 h-2.5 opacity-70"></i>
      </a>
    `).join('');
    this.refreshIcons();
  },

  filterModalCVEs(search) {
    const query = (search || '').trim().toUpperCase();
    const all = this.state.currentModalCVEs || [];
    if (!query) {
      this.renderModalCveBadges(all);
      return;
    }
    const filtered = all.filter(c => c.toUpperCase().includes(query));
    this.renderModalCveBadges(filtered);
  },

  copyModalCVEs() {
    const cves = this.state.currentModalCVEs || [];
    if (!cves.length) return;
    const text = cves.join(', ');
    navigator.clipboard.writeText(text).then(() => {
      const btnText = document.getElementById('btn-copy-cves-text');
      if (btnText) {
        const original = btnText.textContent;
        btnText.textContent = '✓ Copiado!';
        setTimeout(() => { btnText.textContent = original; }, 2000);
      }
    }).catch(err => {
      prompt('Copie as CVEs abaixo:', text);
    });
  },

  async handleSaveTreatment() {
    if ((this.state.user?.role || '').toLowerCase() === 'auditor') {
      alert('Acesso negado: auditores possuem acesso somente leitura e não podem alterar status de tratamento.');
      return;
    }
    const vulnId = document.getElementById('modal-vuln-id').value;
    const status = document.getElementById('modal-treatment-status').value;
    const notesInput = document.getElementById('modal-treatment-notes');
    const notes = notesInput ? notesInput.value.trim() : '';
    const notesError = document.getElementById('modal-treatment-notes-error');
    const saveError = document.getElementById('modal-treatment-save-error');

    // Limpa erros anteriores
    if (notesError) notesError.classList.add('hidden');
    if (saveError) saveError.classList.add('hidden');

    // Valida nota obrigatória
    if (!notes) {
      if (notesError) notesError.classList.remove('hidden');
      if (notesInput) {
        notesInput.classList.add('border-rose-400', 'focus:ring-rose-400');
        notesInput.focus();
      }
      return;
    }
    if (notesInput) notesInput.classList.remove('border-rose-400', 'focus:ring-rose-400');

    const btn = document.getElementById('btn-save-treatment');
    if (btn) { btn.disabled = true; btn.textContent = 'Salvando...'; }

    try {
      await API.updateVulnerabilityTreatment(vulnId, status, notes);

      // Recarrega o histórico sem fechar o modal
      await this._loadTreatmentHistory(vulnId);

      // Atualiza o audit trail do cabeçalho (última alteração)
      const v = await API.getVulnerability(vulnId);
      const auditUser = document.getElementById('modal-treatment-user');
      const auditDate = document.getElementById('modal-treatment-date');
      if (auditUser) auditUser.textContent = v.treated_by_username || '-';
      if (auditDate) auditDate.textContent = v.treated_at ? new Date(v.treated_at).toLocaleString('pt-BR') : '-';

      // Atualiza a lista de vulnerabilidades em background
      this.loadCurrentTabData();
    } catch (e) {
      if (saveError) {
        saveError.textContent = e.message || 'Erro ao salvar tratativa.';
        saveError.classList.remove('hidden');
      }
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Salvar Tratativa'; }
    }
  },

  async _loadTreatmentHistory(vulnId) {
    const listEl = document.getElementById('treatment-history-list');
    const countEl = document.getElementById('treatment-history-count');
    if (!listEl) return;

    listEl.innerHTML = `<div class="text-[11px] text-slate-400 italic text-center py-2">Carregando histórico...</div>`;

    try {
      const history = await API.getTreatmentHistory(vulnId);
      if (countEl) countEl.textContent = `${history.length} registro${history.length !== 1 ? 's' : ''}`;
      this._renderTreatmentHistory(history, listEl);
    } catch {
      listEl.innerHTML = `<div class="text-[11px] text-slate-400 italic text-center py-2">Não foi possível carregar o histórico.</div>`;
    }
  },

  _renderTreatmentHistory(history, listEl) {
    if (!history || history.length === 0) {
      listEl.innerHTML = `<div class="text-[11px] text-slate-400 italic text-center py-3">Nenhuma alteração registrada ainda.</div>`;
      return;
    }

    const statusLabel = {
      'Open':           { label: 'Em Aberto',    cls: 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-400/40' },
      'In_Remediation': { label: 'Em Tratativa', cls: 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-400/40' },
      'In_Action_Plan': { label: 'Em Plano de Ação', cls: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-400 border-indigo-400/40' },
      'Accepted_Risk':  { label: 'Risco Aceito', cls: 'bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-400/40' },
      'Remediated':     { label: 'Remediada',    cls: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-400/40' }
    };

    listEl.innerHTML = history.map((entry, idx) => {
      const s = statusLabel[entry.treatment_status] || { label: entry.treatment_status, cls: 'bg-slate-100 text-slate-600 border-slate-300' };
      const date = new Date(entry.changed_at).toLocaleString('pt-BR');
      const isLatest = idx === 0;
      return `
        <div class="flex gap-2 p-2 rounded-lg border ${isLatest ? 'bg-sky-50/60 dark:bg-sky-950/30 border-sky-200 dark:border-sky-800/50' : 'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800'} text-xs">
          <div class="flex-shrink-0 flex flex-col items-center pt-0.5">
            <div class="w-2 h-2 rounded-full ${isLatest ? 'bg-sky-500' : 'bg-slate-300 dark:bg-slate-600'} mt-0.5"></div>
            ${idx < history.length - 1 ? '<div class="w-px flex-1 bg-slate-200 dark:bg-slate-700 mt-1 min-h-[8px]"></div>' : ''}
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex flex-wrap items-center gap-1.5 mb-0.5">
              <span class="px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${s.cls}">${s.label}</span>
              ${isLatest ? '<span class="text-[9px] font-bold text-sky-600 dark:text-sky-400 uppercase tracking-wider">Atual</span>' : ''}
            </div>
            <p class="text-slate-700 dark:text-slate-300 text-[11px] leading-snug break-words">${this._escHtml(entry.treatment_notes)}</p>
            <div class="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-slate-400">
              <span class="flex items-center gap-1"><i data-lucide="user" class="w-2.5 h-2.5 inline"></i> <strong class="text-slate-600 dark:text-slate-300">${this._escHtml(entry.changed_by_username)}</strong></span>
              <span>•</span>
              <span class="font-mono">${date}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
  },

  _escHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  },

  closeVulnDetailsModal() {
    document.getElementById('vuln-detail-modal')?.classList.add('hidden');
  },

  closePluginSolutionModal() {
    document.getElementById('plugin-solution-modal')?.classList.add('hidden');
  },

  async openPluginSolutionModal(pluginId) {
    const modal = document.getElementById('plugin-solution-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    // Estado inicial de carregamento
    document.getElementById('plugin-modal-title').textContent = 'Carregando solução e dados do plugin...';
    document.getElementById('plugin-modal-id').textContent = pluginId;
    document.getElementById('plugin-modal-solution').textContent = 'Carregando recomendação de correção...';
    document.getElementById('plugin-modal-synopsis').textContent = '...';
    document.getElementById('plugin-modal-description').textContent = '...';
    document.getElementById('plugin-modal-seealso').textContent = '...';
    document.getElementById('plugin-modal-affected-count').textContent = '0';
    document.getElementById('plugin-modal-hosts-badge').textContent = '...';
    const hostsTbody = document.getElementById('plugin-modal-hosts-tbody');
    if (hostsTbody) {
      hostsTbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-400">Carregando lista de ativos afetados...</td></tr>`;
    }

    try {
      const groupId = this.state.selectedAssetGroupId || null;
      const data = await API.getPluginSolution(pluginId, groupId);
      
      this.state.currentPluginSolution = data;
      this.state.currentPluginModalHosts = data.affected_hosts || [];
      this.state.currentPluginModalCVEs = data.cve_list || [];

      // Badges do Cabeçalho
      const sevEl = document.getElementById('plugin-modal-severity');
      if (sevEl) {
        sevEl.textContent = data.severity;
        sevEl.className = `badge-${(data.severity || 'critical').toLowerCase()} px-2.5 py-0.5 rounded text-xs font-bold`;
      }

      const cvssEl = document.getElementById('plugin-modal-cvss');
      if (cvssEl) {
        cvssEl.textContent = data.cvss_v3 ? `CVSS ${data.cvss_v3.toFixed(1)}` : (data.cvss_v2 ? `CVSS ${data.cvss_v2.toFixed(1)}` : 'CVSS -');
      }

      const expEl = document.getElementById('plugin-modal-exploit');
      if (expEl) {
        if (data.exploit_available) {
          expEl.textContent = data.exploit_frameworks ? `SIM (${data.exploit_frameworks.split(',')[0]})` : 'SIM (Exploit público)';
          expEl.className = 'badge-exploit px-2.5 py-0.5 rounded text-xs font-bold';
          expEl.classList.remove('hidden');
        } else {
          expEl.classList.add('hidden');
        }
      }

      document.getElementById('plugin-modal-id').textContent = data.plugin_id;
      const hostCount = data.total_affected_hosts || (data.affected_hosts ? data.affected_hosts.length : 0);
      document.getElementById('plugin-modal-hosts-badge').textContent = `${hostCount} ${hostCount === 1 ? 'Host Afetado' : 'Hosts Afetados'}`;
      document.getElementById('plugin-modal-affected-count').textContent = hostCount;
      document.getElementById('plugin-modal-title').textContent = data.plugin_name;

      // Solução Recomendada
      document.getElementById('plugin-modal-solution').textContent = data.solution || 'Consulte a documentação oficial do fornecedor para atualização ou mitigação.';

      // Tabela de Hosts Afetados
      const hostsSearchInput = document.getElementById('plugin-modal-hosts-search');
      if (hostsSearchInput) hostsSearchInput.value = '';
      this.renderPluginModalHosts(data.affected_hosts || []);

      // CVEs Vinculadas
      const cveCountEl = document.getElementById('plugin-modal-cve-count');
      if (cveCountEl) cveCountEl.textContent = data.cve_count || (data.cve_list ? data.cve_list.length : 0);
      const cveSection = document.getElementById('plugin-modal-cves-section');
      if (cveSection) {
        if (!data.cve_list || data.cve_list.length === 0) {
          cveSection.classList.add('hidden');
        } else {
          cveSection.classList.remove('hidden');
        }
      }
      const cveSearchInput = document.getElementById('plugin-modal-cve-search');
      if (cveSearchInput) cveSearchInput.value = '';
      this.renderPluginModalCveBadges(data.cve_list || []);

      // Sinopse, Descrição Detalhada, Referências
      document.getElementById('plugin-modal-synopsis').textContent = data.synopsis || 'Sem sinopse disponível.';
      document.getElementById('plugin-modal-description').textContent = data.description || 'Sem descrição detalhada disponível.';
      
      const seeAlsoEl = document.getElementById('plugin-modal-seealso');
      if (seeAlsoEl) {
        if (data.see_also) {
          const links = data.see_also.split('\n').filter(Boolean);
          seeAlsoEl.innerHTML = links.map(link => {
            const clean = link.trim();
            if (clean.startsWith('http://') || clean.startsWith('https://')) {
              return `<div><a href="${clean}" target="_blank" rel="noopener noreferrer" class="hover:underline text-sky-400">${clean}</a></div>`;
            }
            return `<div>${clean}</div>`;
          }).join('');
        } else {
          seeAlsoEl.textContent = '-';
        }
      }

      this.refreshIcons();
    } catch (e) {
      document.getElementById('plugin-modal-title').textContent = 'Erro ao carregar detalhes';
      document.getElementById('plugin-modal-solution').textContent = `Falha na requisição: ${e.message}`;
      console.error(e);
    }
  },

  async openPluginDetailsModal(pluginId) {
    return this.openPluginSolutionModal(pluginId);
  },

  renderPluginModalHosts(hosts) {
    const tbody = document.getElementById('plugin-modal-hosts-tbody');
    if (!tbody) return;

    if (!hosts || hosts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Nenhum host afetado encontrado para os filtros atuais.</td></tr>`;
      return;
    }

    tbody.innerHTML = hosts.map(h => {
      const agingColor = h.aging_days > 60 ? 'text-rose-400' : (h.aging_days > 30 ? 'text-amber-400' : 'text-slate-300');
      const firstFoundStr = h.first_found ? new Date(h.first_found).toLocaleDateString('pt-BR') : '-';
      return `
        <tr class="hover:bg-slate-800/50 transition">
          <td class="py-2.5 px-3">
            <div class="font-mono font-bold text-sky-400 cursor-pointer hover:underline" onclick="App.openHostModal(${h.host_id})" title="Ver detalhes do host ${h.ip_address}">${h.ip_address}</div>
          </td>
          <td class="py-2.5 px-3 text-slate-300 font-medium">${h.hostname || '<span class="text-slate-500 italic">Sem hostname</span>'}</td>
          <td class="py-2.5 px-3 font-semibold text-slate-200">
            <span class="inline-block max-w-[220px] truncate align-bottom" title="${h.asset_group_name || '-'}">${h.asset_group_name || '-'}</span>
          </td>
          <td class="py-2.5 px-3 font-mono text-slate-300">${h.port} / ${h.protocol}</td>
          <td class="py-2.5 px-3 text-center">
            <span class="font-bold font-mono ${agingColor}">${h.aging_days} dias</span>
          </td>
          <td class="py-2.5 px-3 font-mono text-slate-400 text-[11px]">${firstFoundStr}</td>
        </tr>
      `;
    }).join('');
    this.refreshIcons();
  },

  filterPluginModalHosts(search) {
    const query = (search || '').trim().toLowerCase();
    const all = this.state.currentPluginModalHosts || [];
    if (!query) {
      this.renderPluginModalHosts(all);
      return;
    }
    const filtered = all.filter(h => 
      (h.ip_address && h.ip_address.toLowerCase().includes(query)) ||
      (h.hostname && h.hostname.toLowerCase().includes(query)) ||
      (h.asset_group_name && h.asset_group_name.toLowerCase().includes(query)) ||
      (h.protocol && h.protocol.toLowerCase().includes(query)) ||
      (String(h.port).includes(query))
    );
    this.renderPluginModalHosts(filtered);
  },

  renderPluginModalCveBadges(cves) {
    const container = document.getElementById('plugin-modal-cves-list');
    if (!container) return;
    if (!cves || cves.length === 0) {
      container.innerHTML = '<span class="text-xs text-slate-500 py-1 px-2">Nenhuma CVE vinculada encontrada.</span>';
      return;
    }
    container.innerHTML = cves.map(cve => `
      <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" rel="noopener noreferrer" 
         class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono bg-sky-950/80 text-sky-300 border border-sky-800/70 hover:bg-sky-900 hover:text-white transition shadow-sm" 
         title="Abrir detalhes oficiais da ${cve} no NIST NVD">
        <span>${cve}</span>
        <i data-lucide="external-link" class="w-2.5 h-2.5 opacity-70"></i>
      </a>
    `).join('');
    this.refreshIcons();
  },

  filterPluginModalCVEs(search) {
    const query = (search || '').trim().toUpperCase();
    const all = this.state.currentPluginModalCVEs || [];
    if (!query) {
      this.renderPluginModalCveBadges(all);
      return;
    }
    const filtered = all.filter(c => c.toUpperCase().includes(query));
    this.renderPluginModalCveBadges(filtered);
  },

  copyPluginModalCVEs() {
    const cves = this.state.currentPluginModalCVEs || [];
    if (!cves.length) return;
    const text = cves.join(', ');
    navigator.clipboard.writeText(text).then(() => {
      const btnText = document.getElementById('btn-copy-plugin-cves-text');
      if (btnText) {
        const original = btnText.textContent;
        btnText.textContent = '✓ Copiado!';
        setTimeout(() => { btnText.textContent = original; }, 2000);
      }
    }).catch(err => {
      prompt('Copie as CVEs abaixo:', text);
    });
  },

  async openHostModal(hostId) {
    const modal = document.getElementById('host-detail-modal');
    if (!modal) return;
    
    document.getElementById('host-modal-ip').textContent = 'Carregando...';
    document.getElementById('host-modal-name').textContent = 'Carregando...';
    document.getElementById('host-modal-os').textContent = 'Carregando...';
    document.getElementById('host-modal-group').textContent = 'Carregando...';
    document.getElementById('host-modal-risk').textContent = '...';
    const tbody = document.getElementById('host-vulns-tbody');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-400">Carregando vulnerabilidades do host...</td></tr>`;
    }
    modal.classList.remove('hidden');

    try {
      const host = await API.getHostDetails(hostId);
      this.state.inventoryCurrentHost = host;
      this.state.inventoryCurrentHostIp = host.ip_address || '';
      document.getElementById('host-modal-ip').textContent = host.ip_address || '-';
      document.getElementById('host-modal-name').textContent = host.hostname || host.netbios_name || 'Sem hostname';
      document.getElementById('host-modal-os').textContent = host.os || 'Não detectado';
      document.getElementById('host-modal-group').textContent = host.asset_group_name || '-';
      document.getElementById('host-modal-risk').textContent = (host.risk_score || 0).toFixed(1);
      
      const rawVulns = await API.listVulnerabilities({ host_id: host.id, scan_id: host.scan_id, exclude_info: true, limit: 500 });
      // Safeguard: strictly exclude info and none findings
      const vulns = (rawVulns || []).filter(v => v.severity && !['info', 'none'].includes(v.severity.toLowerCase()));

      if (tbody) {
        if (!vulns || vulns.length === 0) {
          tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Nenhuma vulnerabilidade acionável (Crítica, Alta, Média ou Baixa) encontrada para este host.</td></tr>`;
        } else {
          tbody.innerHTML = vulns.map(v => `
            <tr class="hover:bg-slate-800/40 transition">
              <td><span class="badge-${(v.severity || 'low').toLowerCase()} px-2 py-0.5 rounded text-xs font-bold">${v.severity}</span></td>
              <td class="font-medium text-slate-200 text-sm">${v.plugin_name}</td>
              <td>${this.formatCveBadge(v.cve, v.cve_list, v.cve_count)}</td>
              <td class="text-xs font-mono text-slate-400">${v.port}/${v.protocol}</td>
              <td class="text-center">${v.exploit_available ? '<span class="badge-exploit px-2 py-0.5 rounded text-xs font-bold">SIM</span>' : '<span class="text-slate-500 text-xs">Não</span>'}</td>
              <td class="text-right">
                <button onclick="App.openVulnDetailsModal(${v.id})" class="px-2 py-0.5 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer">Ver</button>
              </td>
            </tr>
          `).join('');
        }
      }
      this.renderHostActionPlanCard(host);
      this.refreshIcons();
    } catch (e) {
      alert(`Erro ao carregar detalhes do host: ${e.message}`);
    }
  },

  closeHostModal() {
    document.getElementById('host-detail-modal')?.classList.add('hidden');
  },

  renderVulnActionPlanCard(v) {
    const cardEl = document.getElementById('modal-vuln-action-plan-card');
    if (!cardEl) return;

    const tStatus = (v.treatment_status || '').toLowerCase();

    if (tStatus === 'remediated') {
      cardEl.innerHTML = `
        <div class="p-3 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 flex items-center space-x-2.5 text-xs text-emerald-700 dark:text-emerald-300">
          <i data-lucide="check-circle-2" class="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0"></i>
          <span class="font-medium">Vulnerabilidade já remediada. Não é necessária a criação de plano de ação.</span>
        </div>
      `;
      this.refreshIcons();
      return;
    }

    if (v.active_action_plan_id) {
      cardEl.innerHTML = `
        <div class="p-3.5 rounded-xl bg-indigo-50/60 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="flex items-start space-x-3">
            <div class="p-2 rounded-lg bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20 mt-0.5">
              <i data-lucide="clipboard-check" class="w-5 h-5"></i>
            </div>
            <div>
              <div class="text-[10px] font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                <span>Plano de Ação Ativo (ISO 27001 / ISO 9001)</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 font-mono">#${v.active_action_plan_id}</span>
              </div>
              <div class="font-bold text-slate-800 dark:text-slate-100 text-xs sm:text-sm mt-0.5">${this.escapeHtml(v.active_action_plan_title || 'Plano de Ação')}</div>
              <div class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Esta vulnerabilidade está sob governança ativa vinculada a este plano.</div>
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <button type="button" onclick="App.openPlanFromDetails(${v.active_action_plan_id})" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition shadow-xs">
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
              <span>Acessar Plano</span>
            </button>
          </div>
        </div>
      `;
    } else if (tStatus !== 'open') {
      cardEl.innerHTML = `
        <div class="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 flex items-center space-x-2.5 text-xs text-slate-600 dark:text-slate-400">
          <i data-lucide="info" class="w-4 h-4 text-slate-500 flex-shrink-0"></i>
          <span>Vulnerabilidade com status "${this.escapeHtml(v.treatment_status || '')}". Apenas vulnerabilidades com status "Open" são elegíveis para criação de plano de ação.</span>
        </div>
      `;
      this.refreshIcons();
    } else {
      cardEl.innerHTML = `
        <div class="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="flex items-center space-x-2.5 text-xs text-slate-600 dark:text-slate-400">
            <i data-lucide="alert-circle" class="w-4 h-4 text-amber-500 flex-shrink-0"></i>
            <span>Nenhum plano de ação ativo associado a esta ocorrência (Vulnerabilidade Órfã).</span>
          </div>
          <button type="button" onclick="App.openCreatePlanModalFromVuln()" class="px-3 py-1.5 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900 border border-indigo-200 dark:border-indigo-800 text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition flex-shrink-0">
            <i data-lucide="plus-circle" class="w-3.5 h-3.5"></i>
            <span>Criar Plano</span>
          </button>
        </div>
      `;
    }
  },

  renderHostActionPlanCard(host) {
    const cardEl = document.getElementById('host-modal-action-plan-card');
    if (!cardEl) return;

    if (host.active_action_plan_id) {
      cardEl.innerHTML = `
        <div class="p-3.5 rounded-xl bg-indigo-50/60 dark:bg-indigo-950/30 border border-indigo-200 dark:border-indigo-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="flex items-start space-x-3">
            <div class="p-2 rounded-lg bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20 mt-0.5">
              <i data-lucide="clipboard-check" class="w-5 h-5"></i>
            </div>
            <div>
              <div class="text-[10px] font-bold uppercase tracking-wider text-indigo-600 dark:text-indigo-400 flex items-center gap-1.5">
                <span>Plano de Ação Ativo para o Host</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 font-mono">#${host.active_action_plan_id}</span>
              </div>
              <div class="font-bold text-slate-800 dark:text-slate-100 text-xs sm:text-sm mt-0.5">${this.escapeHtml(host.active_action_plan_title || 'Plano de Ação')}</div>
              <div class="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Este ativo possui um plano de remediação estruturado em andamento.</div>
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <button type="button" onclick="App.openPlanFromDetails(${host.active_action_plan_id})" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition shadow-xs">
              <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
              <span>Acessar Plano</span>
            </button>
          </div>
        </div>
      `;
    } else {
      cardEl.innerHTML = `
        <div class="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div class="flex items-center space-x-2.5 text-xs text-slate-600 dark:text-slate-400">
            <i data-lucide="info" class="w-4 h-4 text-slate-400 flex-shrink-0"></i>
            <span>Nenhum plano de ação de host vinculado a este ativo.</span>
          </div>
          <button type="button" onclick="App.openCreatePlanModalFromHost()" class="px-3 py-1.5 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900 border border-indigo-200 dark:border-indigo-800 text-xs font-semibold cursor-pointer flex items-center gap-1.5 transition flex-shrink-0">
            <i data-lucide="plus-circle" class="w-3.5 h-3.5"></i>
            <span>Criar Plano para Host</span>
          </button>
        </div>
      `;
    }
  },

  openPlanFromDetails(planId) {
    this.closeVulnDetailsModal();
    this.closeHostModal();
    this.navigate('actionPlans');
    this.openActionPlanDetail(planId);
  },

  openChangePasswordModal() {
    document.getElementById('change-pwd-old').value = '';
    document.getElementById('change-pwd-new').value = '';
    document.getElementById('change-pwd-error')?.classList.add('hidden');
    document.getElementById('change-pwd-modal')?.classList.remove('hidden');
    this.refreshIcons();
  },

  closeChangePasswordModal() {
    document.getElementById('change-pwd-modal')?.classList.add('hidden');
  },

  async handleChangePassword(e) {
    if (e && e.preventDefault) e.preventDefault();
    const old_password = document.getElementById('change-pwd-old').value;
    const new_password = document.getElementById('change-pwd-new').value;
    const errEl = document.getElementById('change-pwd-error');
    if (errEl) errEl.classList.add('hidden');

    try {
      await API.changePassword(old_password, new_password);
      alert('Senha alterada com sucesso!');
      this.closeChangePasswordModal();
    } catch (err) {
      if (errEl) {
        errEl.textContent = err.message || 'Erro ao alterar senha.';
        errEl.classList.remove('hidden');
      }
    }
  },

  // --- SCAN DIAGNOSTICS & TROUBLESHOOT MODULE ---
  async loadScanDiagnostics() {
    const tbody = document.getElementById('diagnostics-tbody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-400">Verificando erros e diagnósticos de scan...</td></tr>`;

    const groupId = this.state.selectedAssetGroupId || null;
    const categoryFilter = document.getElementById('diag-category-filter')?.value || null;
    const searchFilter = document.getElementById('diag-search-input')?.value.toLowerCase().trim() || '';

    try {
      const data = await API.getScanDiagnostics(groupId, categoryFilter);
      this.state.scanDiagnostics = data;

      // Update KPI Cards
      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
      };

      setVal('diag-kpi-auth', (data.auth_errors_count || 0).toLocaleString());
      setVal('diag-kpi-conn', (data.connection_errors_count || 0).toLocaleString());
      setVal('diag-kpi-perm', (data.permission_errors_count || 0).toLocaleString());
      setVal('diag-kpi-hosts', (data.total_affected_hosts || 0).toLocaleString());

      let items = data.items || [];
      if (searchFilter) {
        items = items.filter(item => 
          (item.host_ip && item.host_ip.toLowerCase().includes(searchFilter)) ||
          (item.host_name && item.host_name.toLowerCase().includes(searchFilter)) ||
          (item.plugin_id && item.plugin_id.toLowerCase().includes(searchFilter)) ||
          (item.plugin_name && item.plugin_name.toLowerCase().includes(searchFilter)) ||
          (item.category && item.category.toLowerCase().includes(searchFilter))
        );
      }

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-8 text-emerald-400 font-medium">Nenhum erro de conexão, ICMP ou autenticação encontrado nos scans deste grupo. Todos os ativos foram escaneados com sucesso!</td></tr>`;
        return;
      }

      tbody.innerHTML = items.map(item => `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="font-mono text-xs text-slate-400 font-bold">${item.plugin_id}</td>
          <td>
            <div class="font-bold text-sky-400 font-mono text-xs">${item.host_ip}</div>
            <div class="text-[11px] text-slate-400">${item.host_name || 'Sem hostname'}</div>
            <div class="text-[10px] text-slate-500">${item.asset_group_name || ''}</div>
          </td>
          <td>
            <span class="px-2 py-0.5 rounded text-xs font-bold ${this.getDiagnosticCategoryBadge(item.category)}">${item.category}</span>
          </td>
          <td>
            <div class="font-semibold text-slate-200 text-xs">${item.error_title}</div>
            <div class="text-[11px] text-slate-400 mt-0.5 line-clamp-2">${item.error_description}</div>
          </td>
          <td>
            <div class="p-2 rounded bg-amber-950/30 border border-amber-800/40 text-[11px] text-amber-200/90 leading-tight">
              <span class="font-bold text-amber-300">Ação para Novo Scan:</span> ${item.recommended_action}
            </div>
          </td>
          <td class="text-right">
            <button onclick="App.openVulnDetailsModal(${item.id})" class="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer">Ver Output</button>
          </td>
        </tr>
      `).join('');

      this.refreshIcons();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-rose-400">Erro ao carregar diagnósticos: ${e.message}</td></tr>`;
    }
  },

  getDiagnosticCategoryBadge(category) {
    if (!category) return 'bg-slate-800 text-slate-300';
    if (category.includes('Autenticação')) return 'bg-rose-500/20 text-rose-300 border border-rose-500/40';
    if (category.includes('Rede') || category.includes('ICMP') || category.includes('Conexão')) return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
    if (category.includes('Permissão') || category.includes('Escalação')) return 'bg-purple-500/20 text-purple-300 border border-purple-500/40';
    return 'bg-sky-500/20 text-sky-300 border border-sky-500/40';
  },

  downloadSampleNessusCsv() {
    window.location.href = '/static/sample_nessus_scan.csv';
  },

  toggleSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    if (sidebar) {
      sidebar.classList.toggle('hidden');
    }
  },

  handleGlobalSearch(query) {
    if (!query || !query.trim()) return;
    const term = query.trim();
    this.navigate('vulnerabilities');
    const searchInput = document.getElementById('vuln-search');
    if (searchInput) {
      searchInput.value = term;
      if (typeof this.filterVulnerabilities === 'function') {
        this.filterVulnerabilities();
      }
    }
  },

  // --- SYSTEM PARAMETERS CONTROLLER (ADMIN ONLY) ---
  async loadParameters() {
    const alertBox = document.getElementById('param-alert');
    if (alertBox) alertBox.classList.add('hidden');

    const auditInfo = document.getElementById('param-audit-info');
    if (auditInfo) {
      auditInfo.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 text-teal-600 animate-spin flex-shrink-0"></i><span>Carregando parâmetros...</span>';
      this.refreshIcons();
    }

    try {
      const promises = [API.getParameters()];
      if (!Array.isArray(this.state.timezones) || this.state.timezones.length === 0) {
        promises.push(API.getTimezones());
      }
      const results = await Promise.all(promises);
      const params = results[0];
      if (results.length > 1 && Array.isArray(results[1])) {
        this.state.timezones = results[1];
      }
      this.state.parameters = params;

      // Populate Timezones select
      const tzSelect = document.getElementById('param-timezone');
      if (tzSelect && Array.isArray(this.state.timezones) && this.state.timezones.length > 0) {
        tzSelect.innerHTML = this.state.timezones.map(tz => {
          const tzId = tz.id || tz.name || '';
          const tzLabel = tz.label || (tz.offset ? `${tzId} (${tz.offset})` : tzId);
          const isSelected = tzId === params.timezone ? 'selected' : '';
          return `<option value="${this.escapeHtml(tzId)}" ${isSelected}>${this.escapeHtml(tzLabel)}</option>`;
        }).join('');
      }

      // Populate SLAs
      const critEl = document.getElementById('param-sla-crit');
      if (critEl) critEl.value = params.sla_critical_days ?? 7;

      const highEl = document.getElementById('param-sla-high');
      if (highEl) highEl.value = params.sla_high_days ?? 15;

      const medEl = document.getElementById('param-sla-med');
      if (medEl) medEl.value = params.sla_medium_days ?? 30;

      const lowEl = document.getElementById('param-sla-low');
      if (lowEl) lowEl.value = params.sla_low_days ?? 60;

      // Populate Ignored IDs
      const ignoredEl = document.getElementById('param-ignored-ids');
      if (ignoredEl) ignoredEl.value = params.ignored_vulnerability_ids || '';

      // Update Tags display & counter
      this.renderIgnoredIdsTags();

      // Update Badges
      const tzBadge = document.getElementById('param-badge-tz-text');
      if (tzBadge) tzBadge.textContent = params.timezone || 'America/Sao_Paulo';

      const fpCount = params.ignored_vulnerabilities_count ?? params.ignored_plugins_count ?? 0;
      const fpBadge = document.getElementById('param-badge-fp-text');
      if (fpBadge) fpBadge.textContent = `${fpCount} Falso(s)-Positivo(s)`;

      // Update Audit Information
      if (auditInfo) {
        const who = params.updated_by_username || 'Sistema';
        const when = params.updated_at_formatted || '-';
        auditInfo.innerHTML = `<i data-lucide="history" class="w-4 h-4 text-slate-400 flex-shrink-0"></i><span>Última parametrização por: <strong class="text-slate-700 dark:text-slate-300 font-semibold">${this.escapeHtml(who)}</strong> em <span class="font-mono">${this.escapeHtml(when)}</span></span>`;
      }

      // Start/Update Live Clock
      this.startLiveClock(params.timezone);

      this.refreshIcons();
    } catch (e) {
      console.error('Error loading parameters:', e);
      if (auditInfo) {
        auditInfo.innerHTML = `<i data-lucide="alert-circle" class="w-4 h-4 text-rose-500 flex-shrink-0"></i><span class="text-rose-500">Erro ao carregar parâmetros: ${this.escapeHtml(e.message)}</span>`;
        this.refreshIcons();
      }
    }
  },

  startLiveClock(timeZone) {
    if (this.state.clockInterval) {
      clearInterval(this.state.clockInterval);
      this.state.clockInterval = null;
    }

    const tz = timeZone || this.state.parameters?.timezone || 'America/Sao_Paulo';

    const tick = () => {
      const clockEl = document.getElementById('param-live-clock');
      const dateEl = document.getElementById('param-live-date');
      const offsetEl = document.getElementById('param-live-offset');

      if (!clockEl && !dateEl) return;

      try {
        const now = new Date();
        if (clockEl) {
          clockEl.textContent = new Intl.DateTimeFormat('pt-BR', {
            timeZone: tz,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
          }).format(now);
        }
        if (dateEl) {
          dateEl.textContent = new Intl.DateTimeFormat('pt-BR', {
            timeZone: tz,
            weekday: 'long',
            day: '2-digit',
            month: 'long',
            year: 'numeric'
          }).format(now);
        }
        if (offsetEl && Array.isArray(this.state.timezones) && this.state.timezones.length > 0) {
          const tzObj = this.state.timezones.find(t => (t.id || t.name) === tz);
          if (tzObj) {
            offsetEl.textContent = tzObj.offset || tzObj.utc_offset_str || tzObj.offset_formatted || 'UTC';
          }
        }
      } catch (err) {
        if (clockEl) clockEl.textContent = new Date().toLocaleTimeString('pt-BR');
      }
    };

    tick();
    this.state.clockInterval = setInterval(tick, 1000);
  },

  handleTimezoneChange() {
    const tzSelect = document.getElementById('param-timezone');
    if (!tzSelect) return;
    const selectedTz = tzSelect.value;
    const tzBadge = document.getElementById('param-badge-tz-text');
    if (tzBadge) tzBadge.textContent = selectedTz;
    this.startLiveClock(selectedTz);
  },

  renderIgnoredIdsTags() {
    const textarea = document.getElementById('param-ignored-ids');
    const tagsContainer = document.getElementById('param-ignored-tags');
    const counter = document.getElementById('param-rules-counter');
    if (!textarea || !tagsContainer) return;

    const raw = textarea.value || '';
    const tokens = raw.split(/[\s,;\n\r\t]+/)
      .map(t => t.trim())
      .filter(t => t.length > 0);

    const uniqueTokens = Array.from(new Set(tokens));

    if (counter) {
      counter.textContent = `${uniqueTokens.length} regra(s) identificada(s)`;
    }

    if (uniqueTokens.length === 0) {
      tagsContainer.innerHTML = '<span class="text-slate-400 italic text-[11px]">Nenhum ID configurado para expurgo no momento.</span>';
      return;
    }

    tagsContainer.innerHTML = uniqueTokens.map(tok => {
      const isKnownScan = tok === '19506';
      const badgeStyle = isKnownScan
        ? 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30'
        : 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30';
      return `
        <span class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-mono font-bold border ${badgeStyle} shadow-xs">
          <span>${this.escapeHtml(tok)}</span>
          <button type="button" onclick="App.removeIgnoredTag('${this.escapeHtml(tok)}')" title="Remover regra" class="hover:text-rose-500 text-slate-400 ml-1 transition cursor-pointer">&times;</button>
        </span>
      `;
    }).join('');
  },

  addDefaultInformationalPlugin() {
    const textarea = document.getElementById('param-ignored-ids');
    if (!textarea) return;
    const raw = textarea.value.trim();
    const tokens = raw ? raw.split(/[\s,;\n\r\t]+/).map(t => t.trim()).filter(Boolean) : [];
    if (!tokens.includes('19506')) {
      tokens.push('19506');
      textarea.value = tokens.join(', ');
      this.renderIgnoredIdsTags();
    }
  },

  removeIgnoredTag(tagToRemove) {
    const textarea = document.getElementById('param-ignored-ids');
    if (!textarea) return;
    const raw = textarea.value.trim();
    const tokens = raw ? raw.split(/[\s,;\n\r\t]+/).map(t => t.trim()).filter(Boolean) : [];
    const filtered = tokens.filter(t => t !== tagToRemove);
    textarea.value = filtered.join(', ');
    this.renderIgnoredIdsTags();
  },

  async handleSaveParameters(e) {
    if (e && e.preventDefault) e.preventDefault();

    const alertBox = document.getElementById('param-alert');
    const alertIcon = document.getElementById('param-alert-icon');
    const alertTitle = document.getElementById('param-alert-title');
    const alertDesc = document.getElementById('param-alert-desc');
    const btnSave = document.getElementById('btn-save-parameters');
    const btnText = document.getElementById('btn-save-param-text');

    if (alertBox) alertBox.classList.add('hidden');

    const tzSelect = document.getElementById('param-timezone');
    const critInput = document.getElementById('param-sla-crit');
    const highInput = document.getElementById('param-sla-high');
    const medInput = document.getElementById('param-sla-med');
    const lowInput = document.getElementById('param-sla-low');
    const ignoredTextarea = document.getElementById('param-ignored-ids');

    const timezone = tzSelect ? tzSelect.value : 'America/Sao_Paulo';
    const slaCrit = critInput ? parseInt(critInput.value, 10) : 7;
    const slaHigh = highInput ? parseInt(highInput.value, 10) : 15;
    const slaMed = medInput ? parseInt(medInput.value, 10) : 30;
    const slaLow = lowInput ? parseInt(lowInput.value, 10) : 60;
    const ignoredIds = ignoredTextarea ? ignoredTextarea.value.trim() : '';

    if (isNaN(slaCrit) || slaCrit <= 0 || isNaN(slaHigh) || slaHigh <= 0 ||
        isNaN(slaMed) || slaMed <= 0 || isNaN(slaLow) || slaLow <= 0) {
      if (alertBox) {
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300 flex items-start space-x-3';
        if (alertIcon) alertIcon.innerHTML = '<i data-lucide="alert-octagon" class="w-5 h-5 text-rose-500"></i>';
        if (alertTitle) alertTitle.textContent = 'Valores de SLA Inválidos';
        if (alertDesc) alertDesc.textContent = 'Todos os prazos de SLA devem ser números inteiros maiores que zero (dias).';
        alertBox.classList.remove('hidden');
        this.refreshIcons();
      }
      return;
    }

    if (btnSave) btnSave.disabled = true;
    if (btnText) btnText.textContent = 'Salvando...';

    try {
      const updated = await API.updateParameters({
        timezone,
        sla_critical_days: slaCrit,
        sla_high_days: slaHigh,
        sla_medium_days: slaMed,
        sla_low_days: slaLow,
        ignored_vulnerability_ids: ignoredIds
      });

      this.state.parameters = updated;

      // Update Badges & Audit
      const tzBadge = document.getElementById('param-badge-tz-text');
      if (tzBadge) tzBadge.textContent = updated.timezone;

      const fpBadge = document.getElementById('param-badge-fp-text');
      if (fpBadge) fpBadge.textContent = `${updated.ignored_plugins_count || 0} Falso(s)-Positivo(s)`;

      const auditInfo = document.getElementById('param-audit-info');
      if (auditInfo) {
        auditInfo.innerHTML = `<i data-lucide="history" class="w-4 h-4 text-slate-400 flex-shrink-0"></i><span>Última parametrização por: <strong class="text-slate-700 dark:text-slate-300 font-semibold">${this.escapeHtml(updated.updated_by_username || 'Sistema')}</strong> em <span class="font-mono">${this.escapeHtml(updated.updated_at_formatted || '-')}</span></span>`;
      }

      this.startLiveClock(updated.timezone);

      if (alertBox) {
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-emerald-500/10 border-emerald-500/30 text-emerald-800 dark:text-emerald-300 flex items-start space-x-3';
        if (alertIcon) alertIcon.innerHTML = '<i data-lucide="check-circle" class="w-5 h-5 text-emerald-500"></i>';
        if (alertTitle) alertTitle.textContent = 'Parâmetros Salvos com Sucesso!';
        if (alertDesc) alertDesc.textContent = `Fuso horário (${updated.timezone}), prazos de SLA (${slaCrit}/${slaHigh}/${slaMed}/${slaLow} dias) e ${updated.ignored_plugins_count} regra(s) de falso-positivo atualizados com êxito. Os indicadores do sistema já foram recalculados.`;
        alertBox.classList.remove('hidden');
      }

      this.refreshIcons();
    } catch (err) {
      if (alertBox) {
        alertBox.className = 'p-4 rounded-xl text-xs font-medium border bg-rose-500/10 border-rose-500/30 text-rose-700 dark:text-rose-300 flex items-start space-x-3';
        if (alertIcon) alertIcon.innerHTML = '<i data-lucide="alert-octagon" class="w-5 h-5 text-rose-500"></i>';
        if (alertTitle) alertTitle.textContent = 'Erro ao Salvar Parâmetros';
        if (alertDesc) alertDesc.textContent = err.message || 'Ocorreu um erro ao atualizar os parâmetros do sistema.';
        alertBox.classList.remove('hidden');
        this.refreshIcons();
      }
    } finally {
      if (btnSave) btnSave.disabled = false;
      if (btnText) btnText.textContent = 'Salvar Parâmetros';
    }
  },

  async handlePreviewIgnored() {
    const textarea = document.getElementById('param-ignored-ids');
    const raw = textarea ? textarea.value.trim() : '';

    const modal = document.getElementById('modal-preview-ignored');
    const kpiPlugins = document.getElementById('preview-kpi-plugins');
    const kpiFindings = document.getElementById('preview-kpi-findings');
    const kpiHosts = document.getElementById('preview-kpi-hosts');
    const tbody = document.getElementById('preview-ignored-tbody');

    if (!modal) return;

    if (kpiPlugins) kpiPlugins.textContent = '...';
    if (kpiFindings) kpiFindings.textContent = '...';
    if (kpiHosts) kpiHosts.textContent = '...';
    if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500 font-sans">Analisando base de dados...</td></tr>';
    modal.classList.remove('hidden');

    try {
      const data = await API.previewIgnoredVulnerabilities(raw);
      const totalRules = data.total_matching_rules ?? data.total_ignored_plugins ?? 0;
      const totalFindings = data.total_findings_affected ?? data.total_findings_impacted ?? 0;
      const totalHosts = data.total_affected_hosts ?? data.total_unique_hosts_impacted ?? 0;

      if (kpiPlugins) kpiPlugins.textContent = totalRules;
      if (kpiFindings) kpiFindings.textContent = totalFindings;
      if (kpiHosts) kpiHosts.textContent = totalHosts;

      if (!data.items || data.items.length === 0) {
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-slate-500 font-sans">Nenhum apontamento correspondente aos IDs informados foi encontrado na base de dados ativa.</td></tr>';
      } else {
        if (tbody) {
          tbody.innerHTML = data.items.map(item => {
            const sevBadge = this.getSeverityBadge(item.severity);
            const findingsCount = item.findings_count ?? item.matching_findings_count ?? 0;
            const hostsCount = item.affected_hosts_count ?? item.impacted_hosts_count ?? 0;
            return `
              <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                <td class="p-3 font-mono font-bold text-teal-600 dark:text-teal-400">${this.escapeHtml(item.plugin_id)}</td>
                <td class="p-3">${sevBadge}</td>
                <td class="p-3 text-slate-800 dark:text-slate-200 font-sans font-medium">${this.escapeHtml(item.plugin_name)}</td>
                <td class="p-3 text-right font-mono font-bold text-amber-600 dark:text-amber-400">${findingsCount}</td>
                <td class="p-3 text-right font-mono text-sky-600 dark:text-sky-400">${hostsCount}</td>
              </tr>
            `;
          }).join('');
        }
      }
      this.refreshIcons();
    } catch (err) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-rose-500 font-sans">Erro na simulação: ${this.escapeHtml(err.message)}</td></tr>`;
    }
  },

  closePreviewIgnoredModal() {
    const modal = document.getElementById('modal-preview-ignored');
    if (modal) modal.classList.add('hidden');
  },

  async handleApplySlasToAllGroups() {
    const critInput = document.getElementById('param-sla-crit');
    const highInput = document.getElementById('param-sla-high');
    const medInput = document.getElementById('param-sla-med');
    const lowInput = document.getElementById('param-sla-low');

    const slaCrit = critInput ? critInput.value : 7;
    const slaHigh = highInput ? highInput.value : 15;
    const slaMed = medInput ? medInput.value : 30;
    const slaLow = lowInput ? lowInput.value : 60;

    const confirmed = confirm(
      `Deseja realmente replicar os prazos de SLA padrão (${slaCrit}d Crítica, ${slaHigh}d Alta, ${slaMed}d Média, ${slaLow}d Baixa) em TODOS os grupos de ativos cadastrados?\n\nEsta operação atualizará as metas de remediação dos grupos.`
    );
    if (!confirmed) return;

    try {
      await API.updateParameters({
        timezone: document.getElementById('param-timezone')?.value || 'America/Sao_Paulo',
        sla_critical_days: parseInt(slaCrit, 10),
        sla_high_days: parseInt(slaHigh, 10),
        sla_medium_days: parseInt(slaMed, 10),
        sla_low_days: parseInt(slaLow, 10),
        ignored_vulnerability_ids: document.getElementById('param-ignored-ids')?.value || ''
      });

      const res = await API.applySlasToAllGroups();
      alert(`Sucesso: ${res.message || 'Prazos de SLA replicados em todos os grupos de ativos.'}`);
      this.loadAssetGroups();
    } catch (err) {
      alert(`Erro ao replicar prazos de SLA: ${err.message}`);
    }
  },

  async fetchInitialParameters() {
    try {
      const params = await API.getParameters();
      this.state.parameters = params;
    } catch (e) {
      // Non-critical on startup
    }
  },

  escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },

  getSeverityBadge(sev) {
    const s = String(sev || '').toLowerCase();
    if (s === 'critical') return '<span class="badge-critical px-2 py-0.5 rounded text-xs font-bold">Critical</span>';
    if (s === 'high') return '<span class="badge-high px-2 py-0.5 rounded text-xs font-bold">High</span>';
    if (s === 'medium') return '<span class="badge-medium px-2 py-0.5 rounded text-xs font-bold">Medium</span>';
    if (s === 'low') return '<span class="badge-low px-2 py-0.5 rounded text-xs font-bold">Low</span>';
    return `<span class="px-2 py-0.5 rounded text-xs font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">${this.escapeHtml(sev || 'Info')}</span>`;
  },

  // =========================================================================
  // MÓDULO GERENCIADOR DE PLANOS DE AÇÃO (PDCA & WBS)
  // =========================================================================

  async loadActionPlansData() {
    const tbody = document.getElementById('action-plans-table-body');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-10 text-slate-400">
        <div class="inline-flex items-center space-x-2">
          <i data-lucide="loader-2" class="w-5 h-5 animate-spin text-indigo-500"></i>
          <span>Carregando planos de ação...</span>
        </div>
      </td></tr>`;
      this.refreshIcons();
    }

    const actionGroupFilter = document.getElementById('action-filter-asset-group');
    if (actionGroupFilter && actionGroupFilter.value !== '') {
      this.state.selectedAssetGroupId = actionGroupFilter.value;
    } else if (actionGroupFilter && this.state.selectedAssetGroupId) {
      actionGroupFilter.value = String(this.state.selectedAssetGroupId);
    }
    const assetGroupId = this.state.selectedAssetGroupId || '';
    const search = document.getElementById('action-filter-search')?.value.trim() || '';
    const status = document.getElementById('action-filter-status')?.value || '';
    const priority = document.getElementById('action-filter-priority')?.value || '';
    const scopeType = document.getElementById('action-filter-scope')?.value || '';
    const tag = document.getElementById('action-filter-tag')?.value || '';

    try {
      const [stats, plans] = await Promise.all([
        API.getActionPlanStats({ asset_group_id: assetGroupId }),
        API.listActionPlans({
          asset_group_id: assetGroupId,
          search,
          status,
          priority,
          scope_type: scopeType,
          tag
        })
      ]);

      this.state.actionPlansStats = stats || null;
      this.state.actionPlansList = plans || [];

      // Update KPI counters
      const kpiTotal = document.getElementById('kpi-action-total');
      if (kpiTotal) kpiTotal.textContent = (stats?.total_plans || 0).toLocaleString();

      const kpiProg = document.getElementById('kpi-action-in-progress');
      if (kpiProg) kpiProg.textContent = (stats?.in_progress_count || 0).toLocaleString();

      const kpiComp = document.getElementById('kpi-action-completed');
      if (kpiComp) kpiComp.textContent = (stats?.completed_count || 0).toLocaleString();

      const kpiOverdue = document.getElementById('kpi-action-overdue');
      if (kpiOverdue) {
        kpiOverdue.textContent = (stats?.overdue_count || 0).toLocaleString();
        if ((stats?.overdue_count || 0) > 0) {
          kpiOverdue.className = 'text-2xl sm:text-3xl font-extrabold tracking-tight text-rose-600 dark:text-rose-400 mt-2 font-mono';
        } else {
          kpiOverdue.className = 'text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-700 dark:text-slate-300 mt-2 font-mono';
        }
      }

      const kpiOverall = document.getElementById('kpi-action-progress');
      if (kpiOverall) kpiOverall.textContent = `${(stats?.overall_progress_percent || 0).toFixed(1)}%`;

      const kpiRatio = document.getElementById('kpi-action-tasks-ratio');
      if (kpiRatio) kpiRatio.textContent = `${stats?.completed_tasks || 0}/${stats?.total_tasks || 0} etapas concluídas`;

      const countBadge = document.getElementById('action-plans-count-badge');
      if (countBadge) countBadge.textContent = `${stats?.total_plans || 0} Planos`;

      // Render view
      if (this.state.actionPlansView === 'kanban') {
        this.renderActionPlansKanban();
      } else {
        this.renderActionPlansList();
      }
    } catch (err) {
      console.error('Erro ao carregar Planos de Ação:', err);
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center py-8 text-rose-500 font-semibold">
          Erro ao carregar planos de ação: ${this.escapeHtml(err.message)}
        </td></tr>`;
      }
    }
  },

  setActionPlansView(viewMode) {
    this.state.actionPlansView = viewMode;
    const btnList = document.getElementById('btn-action-view-list');
    const btnKanban = document.getElementById('btn-action-view-kanban');
    const containerList = document.getElementById('action-plans-list-container');
    const containerKanban = document.getElementById('action-plans-kanban-container');
    const pagination = document.getElementById('action-plans-pagination');

    if (viewMode === 'kanban') {
      if (btnKanban) btnKanban.className = 'px-3 py-1.5 rounded-lg font-semibold flex items-center space-x-1.5 transition cursor-pointer bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-xs';
      if (btnList) btnList.className = 'px-3 py-1.5 rounded-lg font-medium flex items-center space-x-1.5 transition cursor-pointer text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white';
      if (containerList) containerList.classList.add('hidden');
      if (containerKanban) containerKanban.classList.remove('hidden');
      if (pagination) pagination.classList.add('hidden');
      this.renderActionPlansKanban();
    } else {
      if (btnList) btnList.className = 'px-3 py-1.5 rounded-lg font-semibold flex items-center space-x-1.5 transition cursor-pointer bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-xs';
      if (btnKanban) btnKanban.className = 'px-3 py-1.5 rounded-lg font-medium flex items-center space-x-1.5 transition cursor-pointer text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white';
      if (containerKanban) containerKanban.classList.add('hidden');
      if (containerList) containerList.classList.remove('hidden');
      this.renderActionPlansList();
    }
    this.refreshIcons();
  },

  applyActionPlansFilters() {
    this.state.actionPlansPage = 1;
    this.loadActionPlansData();
  },

  handleActionGroupFilterChange(groupId) {
    this.state.actionPlansPage = 1;
    this.state.selectedAssetGroupId = groupId || '';
    const globalFilter = document.getElementById('global-asset-group-filter');
    if (globalFilter) globalFilter.value = groupId || '';
    const actionGroupFilter = document.getElementById('action-filter-asset-group');
    if (actionGroupFilter) actionGroupFilter.value = groupId || '';
    this.loadActionPlansData();
  },

  clearActionPlansFilters() {
    this.state.actionPlansPage = 1;
    const search = document.getElementById('action-filter-search');
    if (search) search.value = '';
    const group = document.getElementById('action-filter-asset-group');
    if (group) group.value = '';
    const st = document.getElementById('action-filter-status');
    if (st) st.value = '';
    const prio = document.getElementById('action-filter-priority');
    if (prio) prio.value = '';
    const sc = document.getElementById('action-filter-scope');
    if (sc) sc.value = '';
    const tag = document.getElementById('action-filter-tag');
    if (tag) tag.value = '';
    this.state.selectedAssetGroupId = '';
    const globalFilter = document.getElementById('global-asset-group-filter');
    if (globalFilter) globalFilter.value = '';
    this.loadActionPlansData();
  },

  getActionPlanPriorityBadge(priority) {
    const p = String(priority || '').toUpperCase();
    if (p === 'CRITICAL') return '<span class="badge-critical px-2 py-0.5 rounded text-[11px] font-bold">Crítica</span>';
    if (p === 'HIGH') return '<span class="badge-high px-2 py-0.5 rounded text-[11px] font-bold">Alta</span>';
    if (p === 'MEDIUM') return '<span class="badge-medium px-2 py-0.5 rounded text-[11px] font-bold">Média</span>';
    if (p === 'LOW') return '<span class="badge-low px-2 py-0.5 rounded text-[11px] font-bold">Baixa</span>';
    return `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">${this.escapeHtml(priority)}</span>`;
  },

  getActionPlanStatusBadge(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'PLANNED') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">Planejado</span>';
    if (s === 'IN_PROGRESS') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">Em Andamento</span>';
    if (s === 'BLOCKED') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">Bloqueado</span>';
    if (s === 'COMPLETED') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">Concluído</span>';
    if (s === 'DRAFT') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">Rascunho</span>';
    if (s === 'CANCELLED') return '<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800">Cancelado</span>';
    return `<span class="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">${this.escapeHtml(status)}</span>`;
  },

  getActionTaskStatusBadge(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'TODO') return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">A Fazer</span>';
    if (s === 'DOING') return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800">Em Execução</span>';
    if (s === 'REVIEW') return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800">Revisão</span>';
    if (s === 'DONE') return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">Concluído</span>';
    if (s === 'BLOCKED') return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800">Bloqueado</span>';
    return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">${this.escapeHtml(status)}</span>`;
  },

  getActionPlanScopeBadge(scopeType, targetInfo, groupName) {
    const sc = String(scopeType || '').toUpperCase();
    let label = 'Customizado';
    let icon = 'layers';
    let color = 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-200 dark:border-slate-700';
    if (sc === 'HOST') {
      label = 'Host';
      icon = 'server';
      color = 'bg-sky-50 text-sky-700 dark:bg-sky-950 dark:text-sky-300 border border-sky-200 dark:border-sky-800';
    } else if (sc === 'VULNERABILITY') {
      label = 'Vulnerabilidade';
      icon = 'shield-alert';
      color = 'bg-rose-50 text-rose-700 dark:bg-rose-950 dark:text-rose-300 border border-rose-200 dark:border-rose-800';
    } else if (sc === 'GROUP') {
      label = 'Grupo de Ativos';
      icon = 'folder-tree';
      color = 'bg-purple-50 text-purple-700 dark:bg-purple-950 dark:text-purple-300 border border-purple-200 dark:border-purple-800';
    } else if (sc === 'MATRIX_NN') {
      label = 'Matriz N:N';
      icon = 'grid';
      color = 'bg-teal-50 text-teal-700 dark:bg-teal-950 dark:text-teal-300 border border-teal-200 dark:border-teal-800';
    }
    return `<div class="space-y-1">
      <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${color}">
        <i data-lucide="${icon}" class="w-3 h-3"></i>
        <span>${label}</span>
      </span>
      ${targetInfo ? `<div class="text-[11px] font-mono text-slate-700 dark:text-slate-200 truncate max-w-[200px]" title="${this.escapeHtml(targetInfo)}">${this.escapeHtml(targetInfo)}</div>` : ''}
      ${groupName ? `<div class="text-[10px] text-teal-700 dark:text-teal-400 font-medium truncate max-w-[200px]" title="Grupo: ${this.escapeHtml(groupName)}"><i data-lucide="folder-tree" class="w-3 h-3 inline mr-0.5 text-teal-600"></i>${this.escapeHtml(groupName)}</div>` : ''}
    </div>`;
  },

  renderActionPlansList() {
    const tbody = document.getElementById('action-plans-table-body');
    const emptyState = document.getElementById('action-plans-empty-state');
    const paginationEl = document.getElementById('action-plans-pagination');
    if (!tbody) return;

    const plans = this.state.actionPlansList || [];
    const total = plans.length;

    if (total === 0) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.classList.remove('hidden');
      if (paginationEl) paginationEl.classList.add('hidden');
      return;
    }

    if (emptyState) emptyState.classList.add('hidden');

    const pageSize = parseInt(this.state.actionPlansPageSize, 10) || 10;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (this.state.actionPlansPage > totalPages) {
      this.state.actionPlansPage = totalPages;
    }
    if (this.state.actionPlansPage < 1) {
      this.state.actionPlansPage = 1;
    }
    const page = this.state.actionPlansPage;
    const startIdx = (page - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, total);
    const pagedPlans = plans.slice(startIdx, endIdx);

    tbody.innerHTML = pagedPlans.map(p => {
      let targetInfo = '';
      if (p.scope_type === 'HOST') {
        targetInfo = p.target_host_ip ? `${p.target_host_ip}${p.target_host_name ? ` (${p.target_host_name})` : ''}` : 'Host não especificado';
      } else if (p.scope_type === 'VULNERABILITY') {
        targetInfo = p.target_plugin_id ? `Plugin #${p.target_plugin_id}` : 'Plugin não especificado';
      } else if (p.scope_type === 'MATRIX_NN') {
        targetInfo = `${(p.scope_host_ips || []).length} Hosts × ${(p.scope_plugin_ids || []).length} Plugins`;
      } else if (p.scope_type === 'GROUP') {
        targetInfo = p.asset_group_name || 'Grupo Global';
      } else {
        targetInfo = p.asset_group_name || 'Geral';
      }

      const dueStr = p.due_date ? new Date(p.due_date).toLocaleDateString('pt-BR') : '-';
      const overdueHtml = p.is_overdue
        ? '<span class="inline-block ml-1 px-1.5 py-0.2 rounded text-[10px] font-bold bg-rose-500 text-white animate-pulse">Atrasado</span>'
        : '';

      const pct = p.progress_percent || 0;
      const barColor = pct === 100 ? 'bg-emerald-500' : (pct > 0 ? 'bg-indigo-600' : 'bg-slate-300 dark:bg-slate-700');

      const tagsHtml = (p.tags && p.tags.length > 0)
        ? `<div class="flex flex-wrap gap-1 mt-1">${p.tags.map(t => `<span class="px-1.5 py-0.2 rounded text-[10px] font-semibold" style="background-color: ${(t.color || '#6366f1')}15; color: ${t.color || '#6366f1'}; border: 1px solid ${(t.color || '#6366f1')}33;">${this.escapeHtml(t.name || t)}</span>`).join('')}</div>`
        : '';

      return `
        <tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition">
          <td class="text-center font-mono font-bold text-slate-500 dark:text-slate-400">#${p.id}</td>
          <td class="max-w-xs">
            <div class="font-bold text-slate-900 dark:text-slate-100 hover:text-indigo-600 dark:hover:text-indigo-400 cursor-pointer transition line-clamp-1" onclick="App.openActionPlanDetail(${p.id})" title="${this.escapeHtml(p.title)}">
              ${this.escapeHtml(p.title)}
            </div>
            ${p.description ? `<div class="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-1 mt-0.5">${this.escapeHtml(p.description)}</div>` : ''}
            ${tagsHtml}
          </td>
          <td>
            ${this.getActionPlanScopeBadge(p.scope_type, targetInfo, p.asset_group_name)}
          </td>
          <td class="text-center">
            ${this.getActionPlanPriorityBadge(p.priority)}
          </td>
          <td class="text-center">
            ${this.getActionPlanStatusBadge(p.status)}
          </td>
          <td>
            <div class="space-y-1">
              <div class="flex items-center justify-between text-[11px]">
                <span class="font-mono font-bold text-slate-700 dark:text-slate-300">${pct.toFixed(0)}%</span>
                <span class="text-slate-400 text-[10px]">${p.completed_tasks}/${p.total_tasks} etapas</span>
              </div>
              <div class="w-full bg-slate-200 dark:bg-slate-800 h-2 rounded-full overflow-hidden">
                <div class="${barColor} h-full rounded-full transition-all duration-300" style="width: ${pct}%"></div>
              </div>
            </div>
          </td>
          <td class="font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap">
            ${dueStr} ${overdueHtml}
          </td>
          <td class="text-slate-700 dark:text-slate-300 whitespace-nowrap">
            <div class="flex items-center space-x-1.5">
              <div class="w-5 h-5 rounded-full bg-indigo-100 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 flex items-center justify-center text-[10px] font-bold">
                ${this.escapeHtml((p.owner_user_name || 'U').charAt(0).toUpperCase())}
              </div>
              <span class="truncate max-w-[120px]" title="${this.escapeHtml(p.owner_user_name || '-')}">${this.escapeHtml(p.owner_user_name || '-')}</span>
            </div>
          </td>
          <td class="text-right whitespace-nowrap">
            <div class="flex items-center justify-end space-x-1">
              <button onclick="App.openActionPlanDetail(${p.id})" class="px-2.5 py-1 text-xs font-semibold rounded-lg bg-indigo-50 hover:bg-indigo-100 dark:bg-indigo-950/50 dark:hover:bg-indigo-900/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 flex items-center space-x-1 cursor-pointer transition shadow-xs" title="Gerenciar Etapas e Detalhes">
                <i data-lucide="list-todo" class="w-3.5 h-3.5"></i>
                <span>Etapas</span>
              </button>
              <button onclick="App.openEditPlanModal(${p.id})" class="p-1 rounded-lg text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer transition" title="Editar Metadados do Plano">
                <i data-lucide="edit-2" class="w-3.5 h-3.5"></i>
              </button>
              <button onclick="App.handleDeletePlan(${p.id})" class="p-1 rounded-lg text-rose-500 hover:text-rose-700 hover:bg-rose-50 dark:hover:bg-rose-950/40 cursor-pointer transition" title="Excluir Plano">
                <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    this.renderActionPlansPagination(total, page, pageSize, totalPages, total === 0 ? 0 : startIdx + 1, endIdx);
    this.refreshIcons();
  },

  renderActionPlansPagination(total, page, pageSize, totalPages, startDisplay, endDisplay) {
    const paginationEl = document.getElementById('action-plans-pagination');
    if (!paginationEl) return;

    if (this.state.actionPlansView === 'kanban' || total === 0) {
      paginationEl.classList.add('hidden');
      return;
    }
    paginationEl.classList.remove('hidden');

    const sizeSelect = document.getElementById('action-plans-page-size');
    if (sizeSelect) sizeSelect.value = String(pageSize);

    const infoEl = document.getElementById('action-plans-page-info');
    if (infoEl) {
      infoEl.textContent = `Página ${page} de ${totalPages} (Mostrando ${startDisplay}-${endDisplay} de ${total} ${total === 1 ? 'plano' : 'planos'})`;
    }

    const prevBtn = document.getElementById('action-plans-prev-btn');
    if (prevBtn) {
      prevBtn.disabled = page <= 1;
    }

    const nextBtn = document.getElementById('action-plans-next-btn');
    if (nextBtn) {
      nextBtn.disabled = page >= totalPages;
    }

    const pillsContainer = document.getElementById('action-plans-page-pills');
    if (pillsContainer) {
      let pillsHtml = '';
      if (totalPages <= 7) {
        for (let i = 1; i <= totalPages; i++) {
          pillsHtml += this.getActionPlanPagePillHtml(i, i === page);
        }
      } else {
        const pages = [];
        pages.push(1);
        let left = Math.max(2, page - 1);
        let right = Math.min(totalPages - 1, page + 1);

        if (left > 2) pages.push('...');
        for (let i = left; i <= right; i++) {
          pages.push(i);
        }
        if (right < totalPages - 1) pages.push('...');
        pages.push(totalPages);

        pages.forEach(p => {
          if (p === '...') {
            pillsHtml += `<span class="px-2 py-1 text-slate-400 text-xs select-none">...</span>`;
          } else {
            pillsHtml += this.getActionPlanPagePillHtml(p, p === page);
          }
        });
      }
      pillsContainer.innerHTML = pillsHtml;
    }
  },

  getActionPlanPagePillHtml(pageNum, isActive) {
    if (isActive) {
      return `<button type="button" class="w-7 h-7 rounded-lg text-xs font-bold bg-indigo-600 text-white shadow-xs select-none cursor-default">${pageNum}</button>`;
    }
    return `<button type="button" onclick="App.setActionPlansPage(${pageNum})" class="w-7 h-7 rounded-lg text-xs font-semibold bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition select-none cursor-pointer">${pageNum}</button>`;
  },

  setActionPlansPage(page) {
    const plans = this.state.actionPlansList || [];
    const pageSize = parseInt(this.state.actionPlansPageSize, 10) || 10;
    const totalPages = Math.max(1, Math.ceil(plans.length / pageSize));
    let targetPage = page;
    if (targetPage < 1) targetPage = 1;
    if (targetPage > totalPages) targetPage = totalPages;
    this.state.actionPlansPage = targetPage;
    this.renderActionPlansList();
    const tableContainer = document.getElementById('action-plans-list-container');
    if (tableContainer) {
      tableContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  },

  handleActionPlansPageSizeChange(val) {
    this.state.actionPlansPageSize = parseInt(val, 10) || 10;
    this.state.actionPlansPage = 1;
    this.renderActionPlansList();
  },

  renderActionPlansKanban() {
    const plans = this.state.actionPlansList || [];
    const groups = {
      planned: [],
      inprogress: [],
      blocked: [],
      completed: [],
      other: []
    };

    plans.forEach(p => {
      const s = (p.status || '').toUpperCase();
      if (s === 'PLANNED' || s === 'DRAFT') groups.planned.push(p);
      else if (s === 'IN_PROGRESS') groups.inprogress.push(p);
      else if (s === 'BLOCKED') groups.blocked.push(p);
      else if (s === 'COMPLETED') groups.completed.push(p);
      else groups.other.push(p);
    });

    const setCnt = (id, count) => {
      const el = document.getElementById(id);
      if (el) el.textContent = count;
    };
    setCnt('kanban-count-planned', groups.planned.length);
    setCnt('kanban-count-inprogress', groups.inprogress.length);
    setCnt('kanban-count-blocked', groups.blocked.length);
    setCnt('kanban-count-completed', groups.completed.length);
    setCnt('kanban-count-other', groups.other.length);

    const renderCard = (p) => {
      const dueStr = p.due_date ? new Date(p.due_date).toLocaleDateString('pt-BR') : '-';
      const pct = p.progress_percent || 0;
      const barColor = pct === 100 ? 'bg-emerald-500' : 'bg-indigo-600';
      const scopeDesc = p.scope_type === 'MATRIX_NN'
        ? `${(p.scope_host_ips || []).length} Hosts × ${(p.scope_plugin_ids || []).length} Plugins`
        : (p.target_host_ip || p.target_plugin_id || p.asset_group_name || 'Geral');

      return `
        <div onclick="App.openActionPlanDetail(${p.id})" class="p-3.5 rounded-xl bg-white dark:bg-[#131B2E] border border-slate-200 dark:border-slate-800 shadow-xs hover:shadow-md hover:border-indigo-300 dark:hover:border-indigo-800/80 transition cursor-pointer space-y-2.5">
          <div class="flex items-center justify-between gap-1.5">
            ${this.getActionPlanPriorityBadge(p.priority)}
            <span class="font-mono text-[10px] text-slate-400">#${p.id}</span>
          </div>
          <h5 class="font-bold text-xs text-slate-800 dark:text-slate-100 line-clamp-2 leading-snug">
            ${this.escapeHtml(p.title)}
          </h5>
          <div class="text-[11px] text-slate-500 dark:text-slate-400 truncate">
            <i data-lucide="tag" class="w-3 h-3 inline mr-1 text-slate-400"></i>
            <span>${this.escapeHtml(p.scope_type)}: ${this.escapeHtml(scopeDesc)}</span>
          </div>
          ${(p.tags && p.tags.length > 0) ? `
            <div class="flex flex-wrap gap-1">
              ${p.tags.map(t => `<span class="px-1.5 py-0.2 rounded text-[9px] font-semibold" style="background-color: ${(t.color || '#6366f1')}15; color: ${t.color || '#6366f1'}; border: 1px solid ${(t.color || '#6366f1')}33;">${this.escapeHtml(t.name || t)}</span>`).join('')}
            </div>
          ` : ''}
          ${p.asset_group_name ? `
            <div class="text-[10px] text-teal-600 dark:text-teal-400 font-medium truncate" title="Grupo: ${this.escapeHtml(p.asset_group_name)}">
              <i data-lucide="folder-tree" class="w-3 h-3 inline mr-0.5"></i>
              ${this.escapeHtml(p.asset_group_name)}
            </div>
          ` : ''}
          <div class="space-y-1 pt-1 border-t border-slate-100 dark:border-slate-800/60">
            <div class="flex items-center justify-between text-[10px]">
              <span class="text-slate-400">${p.completed_tasks}/${p.total_tasks} etapas</span>
              <span class="font-bold font-mono text-slate-700 dark:text-slate-300">${pct.toFixed(0)}%</span>
            </div>
            <div class="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
              <div class="${barColor} h-full rounded-full" style="width: ${pct}%"></div>
            </div>
          </div>
          <div class="flex items-center justify-between text-[10px] pt-1 text-slate-400">
            <span class="${p.is_overdue ? 'text-rose-500 font-bold' : ''}">
              <i data-lucide="calendar" class="w-3 h-3 inline mr-0.5"></i>
              ${dueStr} ${p.is_overdue ? '(Atrasado)' : ''}
            </span>
            <span class="truncate max-w-[80px]" title="${this.escapeHtml(p.owner_user_name || '-')}">
              ${this.escapeHtml(p.owner_user_name || '-')}
            </span>
          </div>
        </div>
      `;
    };

    ['planned', 'inprogress', 'blocked', 'completed', 'other'].forEach(col => {
      const el = document.getElementById(`kanban-col-${col}`);
      if (el) {
        if (groups[col].length === 0) {
          el.innerHTML = '<div class="text-center py-8 text-xs text-slate-400 italic">Nenhum plano</div>';
        } else {
          el.innerHTML = groups[col].map(renderCard).join('');
        }
      }
    });

    this.refreshIcons();
  },

  // ============================================================
  // ACTION PLAN OWNER COMBOBOX (SEARCH & DROPDOWN)
  // ============================================================
  initPlanOwnerDropdown(defaultUserId = null) {
    const assignees = this.state.actionPlansAssignees || [];
    let selectedId = defaultUserId;
    const currentUserId = this.state.user?.id;

    if (!selectedId && currentUserId && assignees.some(u => String(u.id) === String(currentUserId))) {
      selectedId = currentUserId;
    } else if (!selectedId && assignees.length > 0) {
      selectedId = assignees[0].id;
    }

    if (selectedId != null) {
      this.selectPlanOwner(selectedId, false);
    }
  },

  renderPlanOwnerDropdownItems(users, selectedId) {
    const dropdown = document.getElementById('plan-form-owner-dropdown');
    if (!dropdown) return;

    if (!users || users.length === 0) {
      dropdown.innerHTML = `
        <div class="px-3 py-3 text-center text-slate-400 text-xs">
          Nenhum responsável encontrado para a busca
        </div>
      `;
      return;
    }

    dropdown.innerHTML = users.map(u => {
      const isSelected = String(u.id) === String(selectedId);
      const name = this.escapeHtml(u.full_name || u.username);
      const uname = this.escapeHtml(u.username);
      const role = this.escapeHtml(u.role || 'Usuário');
      const initial = (u.full_name || u.username || 'U').charAt(0).toUpperCase();

      return `
        <div 
          onclick="App.selectPlanOwner(${u.id})"
          class="flex items-center justify-between px-3 py-2 cursor-pointer transition select-none ${
            isSelected
              ? 'bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 font-semibold'
              : 'hover:bg-slate-50 dark:hover:bg-slate-800/80 text-slate-700 dark:text-slate-200'
          }"
        >
          <div class="flex items-center space-x-2.5 min-w-0">
            <div class="w-6 h-6 rounded-full bg-indigo-100 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 flex items-center justify-center text-[10px] font-bold shrink-0">
              ${initial}
            </div>
            <div class="min-w-0">
              <div class="truncate text-xs">${name}</div>
              <div class="text-[10px] text-slate-400">@${uname} • <span class="capitalize">${role}</span></div>
            </div>
          </div>
          ${isSelected ? '<i data-lucide="check" class="w-3.5 h-3.5 text-indigo-600 dark:text-indigo-400 shrink-0"></i>' : ''}
        </div>
      `;
    }).join('');

    this.refreshIcons();
  },

  openPlanOwnerDropdown() {
    const dropdown = document.getElementById('plan-form-owner-dropdown');
    const chevron = document.getElementById('plan-form-owner-chevron');
    if (!dropdown) return;
    dropdown.classList.remove('hidden');
    if (chevron) chevron.classList.add('rotate-180');

    const searchInput = document.getElementById('plan-form-owner-search');
    const currentQuery = searchInput?.value?.trim() || '';
    const selectedId = document.getElementById('plan-form-owner')?.value;
    
    const selectedUser = (this.state.actionPlansAssignees || []).find(u => String(u.id) === String(selectedId));
    const selectedLabel = selectedUser ? `${selectedUser.full_name || selectedUser.username} (@${selectedUser.username})` : '';

    if (currentQuery === selectedLabel || !currentQuery) {
      this.renderPlanOwnerDropdownItems(this.state.actionPlansAssignees || [], selectedId);
    } else {
      this.filterPlanOwnerOptions(currentQuery);
    }
  },

  closePlanOwnerDropdown() {
    const dropdown = document.getElementById('plan-form-owner-dropdown');
    const chevron = document.getElementById('plan-form-owner-chevron');
    if (!dropdown) return;
    dropdown.classList.add('hidden');
    if (chevron) chevron.classList.remove('rotate-180');

    const selectedId = document.getElementById('plan-form-owner')?.value;
    const selectedUser = (this.state.actionPlansAssignees || []).find(u => String(u.id) === String(selectedId)) ||
                         (this.state.user && String(this.state.user.id) === String(selectedId) ? this.state.user : null);
    const searchInput = document.getElementById('plan-form-owner-search');
    if (searchInput && selectedUser) {
      searchInput.value = `${selectedUser.full_name || selectedUser.username} (@${selectedUser.username})`;
    }
  },

  togglePlanOwnerDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('plan-form-owner-dropdown');
    if (dropdown && !dropdown.classList.contains('hidden')) {
      this.closePlanOwnerDropdown();
    } else {
      this.openPlanOwnerDropdown();
      document.getElementById('plan-form-owner-search')?.focus();
    }
  },

  filterPlanOwnerOptions(query) {
    const dropdown = document.getElementById('plan-form-owner-dropdown');
    const chevron = document.getElementById('plan-form-owner-chevron');
    if (dropdown && dropdown.classList.contains('hidden')) {
      dropdown.classList.remove('hidden');
      if (chevron) chevron.classList.add('rotate-180');
    }

    const q = (query || '').toLowerCase().trim();
    const assignees = this.state.actionPlansAssignees || [];
    const selectedId = document.getElementById('plan-form-owner')?.value;

    if (!q) {
      this.renderPlanOwnerDropdownItems(assignees, selectedId);
      return;
    }

    const filtered = assignees.filter(u => {
      const fullName = (u.full_name || '').toLowerCase();
      const uname = (u.username || '').toLowerCase();
      const role = (u.role || '').toLowerCase();
      return fullName.includes(q) || uname.includes(q) || role.includes(q) || `@${uname}`.includes(q);
    });

    this.renderPlanOwnerDropdownItems(filtered, selectedId);
  },

  selectPlanOwner(userId, shouldClose = true) {
    const select = document.getElementById('plan-form-owner');
    if (select) {
      select.value = String(userId);
    }
    const user = (this.state.actionPlansAssignees || []).find(u => String(u.id) === String(userId)) ||
                 (this.state.user && String(this.state.user.id) === String(userId) ? this.state.user : null);

    const searchInput = document.getElementById('plan-form-owner-search');
    if (searchInput && user) {
      searchInput.value = `${user.full_name || user.username} (@${user.username})`;
    }

    if (shouldClose) {
      const dropdown = document.getElementById('plan-form-owner-dropdown');
      const chevron = document.getElementById('plan-form-owner-chevron');
      if (dropdown) dropdown.classList.add('hidden');
      if (chevron) chevron.classList.remove('rotate-180');
    }
  },

  async populateActionPlanFormSelectors() {
    // 1. Assignees
    try {
      if (!this.state.actionPlansAssignees || this.state.actionPlansAssignees.length === 0) {
        this.state.actionPlansAssignees = await API.getActionPlanAssignees();
      }
      const ownerSelect = document.getElementById('plan-form-owner');
      const taskAssigneeSelect = document.getElementById('task-form-assignee');
      
      const currentUserId = this.state.user?.id;
      let optionsHtml = (this.state.actionPlansAssignees || []).map(u => `
        <option value="${u.id}" ${u.id === currentUserId ? 'selected' : ''}>
          ${this.escapeHtml(u.full_name || u.username)} (@${this.escapeHtml(u.username)} - ${this.escapeHtml(u.role)})
        </option>
      `).join('');

      if (!optionsHtml && this.state.user) {
        optionsHtml = `<option value="${this.state.user.id || 1}" selected>${this.escapeHtml(this.state.user.full_name || this.state.user.username || 'Admin')}</option>`;
      }

      if (ownerSelect) ownerSelect.innerHTML = optionsHtml;
      if (taskAssigneeSelect) taskAssigneeSelect.innerHTML = `<option value="">Mesmo responsável do Plano</option>` + optionsHtml;

      this.initPlanOwnerDropdown(currentUserId);
    } catch (e) {
      console.error('Erro ao carregar lista de responsáveis:', e);
      const ownerSelect = document.getElementById('plan-form-owner');
      if (ownerSelect && (!ownerSelect.options || ownerSelect.options.length === 0)) {
        const uid = this.state.user?.id || 1;
        const uname = this.state.user?.username || 'Admin';
        ownerSelect.innerHTML = `<option value="${uid}" selected>${this.escapeHtml(uname)}</option>`;
      }
      this.initPlanOwnerDropdown(this.state.user?.id || 1);
    }

    // 2. Asset Groups (hierárquico multinível - sem opção global)
    const groupSelect = document.getElementById('plan-form-asset-group');
    if (groupSelect) {
      if (!this.state.assetGroups || this.state.assetGroups.length === 0) {
        try {
          this.state.assetGroups = await API.listAssetGroups();
        } catch (e) {
          console.warn('Erro ao carregar grupos de ativos:', e);
        }
      }
      groupSelect.innerHTML = this.getHierarchicalGroupOptions(false);

      const hierarchical = this.buildHierarchicalGroupList(this.state.assetGroups || []);
      const firstAllowedGroupId = hierarchical.length > 0 ? String(hierarchical[0].id) : (this.state.assetGroups?.[0]?.id ? String(this.state.assetGroups[0].id) : '');

      if (this.state.selectedAssetGroupId && this.state.assetGroups?.some(g => String(g.id) === String(this.state.selectedAssetGroupId))) {
        groupSelect.value = String(this.state.selectedAssetGroupId);
      } else if (firstAllowedGroupId) {
        groupSelect.value = firstAllowedGroupId;
      }
    }

    // Sincroniza também o filtro da barra de ferramentas da tela de planos
    const actionGroupFilter = document.getElementById('action-filter-asset-group');
    if (actionGroupFilter) {
      actionGroupFilter.innerHTML = this.getHierarchicalGroupOptions(true, 'Grupo: Todos');
      if (this.state.selectedAssetGroupId) {
        actionGroupFilter.value = String(this.state.selectedAssetGroupId);
      }
    }

    // 3. Hosts for target picker
    const hostSelect = document.getElementById('plan-form-target-host');
    if (hostSelect) {
      try {
        const targetGroup = groupSelect?.value || this.state.selectedAssetGroupId || '';
        const hosts = await API.getUniqueHosts(targetGroup);
        hostSelect.innerHTML = `<option value="">Selecione um host...</option>` + (hosts || []).map(h => {
          const val = (h.id != null) ? h.id : (h.ip || h.ip_address);
          const displayIp = h.ip || h.ip_address || '';
          const displayName = h.hostname ? ` (${h.hostname})` : '';
          return `<option value="${val}">${this.escapeHtml(displayIp)}${this.escapeHtml(displayName)}</option>`;
        }).join('');
      } catch (e) {
        console.error('Erro ao carregar lista de hosts:', e);
      }
    }

    // 4. Tags
    try {
      const tags = await API.getActionPlanTags();
      this.state.actionPlanTags = tags || [];
      const suggEl = document.getElementById('plan-form-tag-suggestions');
      if (suggEl) {
        if (tags && tags.length > 0) {
          suggEl.innerHTML = tags.map(t => `
            <button type="button" onclick="App.appendPlanTag('${this.escapeHtml(t.name)}')" class="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900 cursor-pointer transition">
              + ${this.escapeHtml(t.name)}
            </button>
          `).join('');
        } else {
          suggEl.innerHTML = '';
        }
      }

      const filterTagSelect = document.getElementById('action-filter-tag');
      if (filterTagSelect) {
        const currentVal = filterTagSelect.value;
        filterTagSelect.innerHTML = `<option value="">Tag: Todas</option>` + (tags || []).map(t => `
          <option value="${this.escapeHtml(t.name)}">${this.escapeHtml(t.name)}</option>
        `).join('');
        if (currentVal) filterTagSelect.value = currentVal;
      }
    } catch (e) {
      console.warn('Erro ao carregar tags:', e);
    }
  },

  appendPlanTag(tagName) {
    const input = document.getElementById('plan-form-tags');
    if (!input) return;
    const existing = input.value.split(',').map(s => s.trim()).filter(Boolean);
    if (!existing.includes(tagName)) {
      existing.push(tagName);
      input.value = existing.join(', ');
    }
  },

  async handlePlanFormAssetGroupChange() {
    this.state.planWizardSelectedHosts = [];
    this.state.planWizardSelectedPlugins = [];
    this.state.planWizardHostOsFilter = '';
    const osSelect = document.getElementById('plan-wizard-host-os-filter');
    if (osSelect) osSelect.value = '';
    this.renderWizardSelectedHosts();
    this.renderWizardSelectedPlugins();
    const groupId = document.getElementById('plan-form-asset-group')?.value || '';
    await this.loadWizardOsOptions(groupId);
    if (this.state.planWizardStep === 2) {
      this.loadWizardCandidateHosts();
    } else if (this.state.planWizardStep === 3) {
      this.loadWizardCandidateVulns();
    }
    this.updateWizardImpactPreview();
  },

  handleScopeTypeChange() {},

  // ============================================================
  // PLAN WIZARD (3-STEP WIZARD) NAVIGATION & STATE MANAGEMENT
  // ============================================================
  goToPlanWizardStep(step) {
    const titleVal = document.getElementById('plan-form-title')?.value?.trim();
    if (step > 1 && !titleVal) {
      alert('Por favor, informe o título do plano de ação na Etapa 1 antes de avançar.');
      this.goToPlanWizardStep(1);
      document.getElementById('plan-form-title')?.focus();
      return;
    }

    const groupVal = document.getElementById('plan-form-asset-group')?.value;
    if (step > 1 && !groupVal) {
      alert('Por favor, selecione um Grupo de Ativos na Etapa 1 antes de avançar.');
      this.goToPlanWizardStep(1);
      document.getElementById('plan-form-asset-group')?.focus();
      return;
    }

    this.state.planWizardStep = step;

    // Toggle panels
    const p1 = document.getElementById('plan-wizard-panel-1');
    const p2 = document.getElementById('plan-wizard-panel-2');
    const p3 = document.getElementById('plan-wizard-panel-3');

    if (p1) p1.classList.toggle('hidden', step !== 1);
    if (p2) p2.classList.toggle('hidden', step !== 2);
    if (p3) p3.classList.toggle('hidden', step !== 3);

    // Update Tabs
    this.updatePlanWizardTabs(step);

    if (step === 2) {
      const groupId = document.getElementById('plan-form-asset-group')?.value || '';
      this.loadWizardOsOptions(groupId);
      this.loadWizardCandidateHosts(document.getElementById('plan-wizard-host-search')?.value || '');
      this.renderWizardSelectedHosts();
    } else if (step === 3) {
      this.setupWizardStep3View();
      this.updateWizardImpactPreview();
    }

    this.refreshIcons();
  },

  updatePlanWizardTabs(step) {
    for (let i = 1; i <= 3; i++) {
      const tab = document.getElementById(`plan-wizard-tab-${i}`);
      const badge = document.getElementById(`plan-wizard-badge-${i}`);
      if (!tab || !badge) continue;

      if (i === step) {
        tab.className = 'flex items-center gap-2.5 p-2.5 rounded-xl transition text-left cursor-pointer bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-300 dark:border-indigo-700 shadow-xs';
        badge.className = 'w-6 h-6 rounded-lg flex items-center justify-center font-bold text-xs bg-indigo-600 text-white shrink-0';
      } else if (i < step) {
        tab.className = 'flex items-center gap-2.5 p-2.5 rounded-xl transition text-left cursor-pointer bg-emerald-50/70 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/60';
        badge.className = 'w-6 h-6 rounded-lg flex items-center justify-center font-bold text-xs bg-emerald-600 text-white shrink-0';
      } else {
        tab.className = 'flex items-center gap-2.5 p-2.5 rounded-xl transition text-left cursor-pointer bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 opacity-60';
        badge.className = 'w-6 h-6 rounded-lg flex items-center justify-center font-bold text-xs bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 shrink-0';
      }
    }
  },

  // --- HOST SELECTION (ETAPA 2) ---
  async loadWizardOsOptions(groupId) {
    const osSelect = document.getElementById('plan-wizard-host-os-filter');
    if (!osSelect) return;

    try {
      const osList = await API.getWizardOsList(groupId || '');
      const currentSelected = this.state.planWizardHostOsFilter || '';

      let html = '<option value="">SO: Todos os Sistemas</option>';
      (osList || []).forEach(os => {
        const sel = (os === currentSelected) ? 'selected' : '';
        html += `<option value="${this.escapeHtml(os)}" ${sel}>${this.escapeHtml(os)}</option>`;
      });
      osSelect.innerHTML = html;
      if (!osList.includes(currentSelected)) {
        this.state.planWizardHostOsFilter = '';
        osSelect.value = '';
      }
    } catch (e) {
      console.warn('Erro ao carregar lista de SOs do wizard:', e);
      osSelect.innerHTML = '<option value="">SO: Todos os Sistemas</option>';
    }
  },

  handleWizardHostOsChange(val) {
    this.state.planWizardHostOsFilter = val || '';
    const searchVal = document.getElementById('plan-wizard-host-search')?.value || '';
    this.loadWizardCandidateHosts(searchVal);
  },

  wizardHostSearchTimeout: null,
  handleWizardHostSearch(val) {
    clearTimeout(this.wizardHostSearchTimeout);
    this.wizardHostSearchTimeout = setTimeout(() => {
      this.loadWizardCandidateHosts(val);
    }, 250);
  },

  async loadWizardCandidateHosts(search = '') {
    const listEl = document.getElementById('plan-wizard-candidate-hosts');
    if (!listEl) return;

    listEl.innerHTML = `<div class="text-center py-2 text-[11px] text-slate-400"><i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin inline mr-1 text-indigo-500"></i>Buscando hosts...</div>`;
    this.refreshIcons();

    try {
      const groupId = document.getElementById('plan-form-asset-group')?.value || '';
      const planId = document.getElementById('action-plan-id')?.value || '';
      const osFilter = this.state.planWizardHostOsFilter || '';
      const hosts = await API.getWizardHosts(groupId, search, planId, osFilter);
      this.state.planWizardCandidateHosts = hosts || [];
      this.renderWizardCandidateHosts();
    } catch (err) {
      listEl.innerHTML = `<div class="text-center py-2 text-[11px] text-rose-500">Erro ao listar hosts: ${this.escapeHtml(err.message)}</div>`;
    }
  },

  renderWizardCandidateHosts() {
    const listEl = document.getElementById('plan-wizard-candidate-hosts');
    if (!listEl) return;

    const hosts = this.state.planWizardCandidateHosts || [];
    if (hosts.length === 0) {
      listEl.innerHTML = `<div class="text-center py-3 text-[11px] text-slate-400">Nenhum host com apontamentos ativos encontrado para este filtro.</div>`;
      return;
    }

    const selectedIps = new Set((this.state.planWizardSelectedHosts || []).map(h => h.ip));

    listEl.innerHTML = hosts.map(h => {
      const isAdded = selectedIps.has(h.ip);
      const ipEscaped = this.escapeHtml(h.ip);
      return `
        <div class="flex items-center justify-between p-2 rounded-lg hover:bg-white dark:hover:bg-slate-800/80 transition border ${isAdded ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20' : 'border-transparent hover:border-slate-200 dark:hover:border-slate-700'} text-[11px]">
          <div class="flex items-center gap-2 min-w-0">
            <span class="w-6 h-6 rounded-md flex items-center justify-center bg-indigo-50 dark:bg-indigo-950 text-indigo-600 dark:text-indigo-400 shrink-0">
              <i data-lucide="server" class="w-3.5 h-3.5"></i>
            </span>
            <div class="min-w-0">
              <div class="font-bold text-slate-800 dark:text-slate-200 truncate flex items-center gap-1.5">
                <span>${ipEscaped}</span>
                ${h.hostname ? `<span class="text-slate-400 font-normal truncate">(${this.escapeHtml(h.hostname)})</span>` : ''}
              </div>
              <div class="flex items-center gap-1.5 text-[10px] text-slate-500 dark:text-slate-400 flex-wrap">
                <span>${this.escapeHtml(h.asset_group_name || 'Global')}</span>
                ${h.os ? `<span class="px-1.5 py-0.2 rounded text-[10px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 truncate max-w-[140px]" title="SO: ${this.escapeHtml(h.os)}"><i data-lucide="cpu" class="w-2.5 h-2.5 inline mr-0.5"></i>${this.escapeHtml(h.os)}</span>` : ''}
                <span>•</span>
                <span class="font-semibold text-indigo-600 dark:text-indigo-400">${h.vuln_count} vulns</span>
                ${h.critical_count > 0 ? `<span class="badge-critical px-1 rounded font-bold">${h.critical_count} Críticas</span>` : ''}
                ${h.high_count > 0 ? `<span class="badge-high px-1 rounded font-bold">${h.high_count} Altas</span>` : ''}
              </div>
            </div>
          </div>

          <button type="button" onclick="App.toggleWizardHostItem('${ipEscaped}')" class="px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer transition shrink-0 ${
            isAdded 
              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
              : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-xs'
          }">
            ${isAdded ? '✓ Adicionado' : '+ Adicionar'}
          </button>
        </div>
      `;
    }).join('');
    this.refreshIcons();
  },

  toggleWizardHostItem(ipOrHost) {
    if (!this.state.planWizardSelectedHosts) this.state.planWizardSelectedHosts = [];
    const ip = (typeof ipOrHost === 'object' && ipOrHost !== null) ? ipOrHost.ip : String(ipOrHost);
    const idx = this.state.planWizardSelectedHosts.findIndex(h => h.ip === ip);
    if (idx >= 0) {
      this.state.planWizardSelectedHosts.splice(idx, 1);
    } else {
      const candidate = (this.state.planWizardCandidateHosts || []).find(h => h.ip === ip);
      if (candidate) {
        this.state.planWizardSelectedHosts.push({ ...candidate });
      } else if (typeof ipOrHost === 'object') {
        this.state.planWizardSelectedHosts.push(ipOrHost);
      }
    }
    this.renderWizardSelectedHosts();
    this.renderWizardCandidateHosts();
  },

  selectAllCandidateHosts() {
    if (!this.state.planWizardSelectedHosts) this.state.planWizardSelectedHosts = [];
    const selectedIps = new Set(this.state.planWizardSelectedHosts.map(h => h.ip));
    const candidates = this.state.planWizardCandidateHosts || [];
    for (const c of candidates) {
      if (!selectedIps.has(c.ip)) {
        this.state.planWizardSelectedHosts.push({ ...c });
        selectedIps.add(c.ip);
      }
    }
    this.renderWizardSelectedHosts();
    this.renderWizardCandidateHosts();
  },

  removeWizardHost(ip) {
    if (!this.state.planWizardSelectedHosts) return;
    this.state.planWizardSelectedHosts = this.state.planWizardSelectedHosts.filter(h => h.ip !== ip);
    this.renderWizardSelectedHosts();
    this.renderWizardCandidateHosts();
    if (this.state.planWizardStep === 3) {
      this.updateWizardImpactPreview();
    }
  },

  clearWizardHosts() {
    this.state.planWizardSelectedHosts = [];
    this.renderWizardSelectedHosts();
    this.renderWizardCandidateHosts();
    if (this.state.planWizardStep === 3) {
      this.updateWizardImpactPreview();
    }
  },

  renderWizardSelectedHosts() {
    const listEl = document.getElementById('plan-wizard-selected-hosts-list');
    const countBadge = document.getElementById('plan-wizard-selected-hosts-count');
    const clearBtn = document.getElementById('btn-clear-wizard-hosts');
    const hosts = this.state.planWizardSelectedHosts || [];

    if (countBadge) countBadge.textContent = String(hosts.length);
    if (clearBtn) clearBtn.classList.toggle('hidden', hosts.length === 0);

    if (!listEl) return;

    if (hosts.length === 0) {
      listEl.innerHTML = `
        <div class="text-center py-4 text-slate-400 text-[11px] space-y-1">
          <p class="font-medium text-slate-500 dark:text-slate-400">Nenhum host específico selecionado.</p>
          <p class="text-[10px] text-slate-400">Ao avançar sem hosts, o plano terá escopo por Vulnerabilidade (Plugin) e abrangerá todos os hosts do grupo.</p>
        </div>
      `;
      return;
    }

    listEl.innerHTML = hosts.map(h => `
      <div class="flex items-center justify-between p-2 rounded-lg bg-white dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700/80 shadow-2xs text-[11px]">
        <div class="flex items-center gap-2 min-w-0">
          <span class="w-6 h-6 rounded-md flex items-center justify-center bg-indigo-50 dark:bg-indigo-950/80 text-indigo-600 dark:text-indigo-400 shrink-0">
            <i data-lucide="shield-check" class="w-3.5 h-3.5"></i>
          </span>
          <div class="min-w-0">
            <div class="font-bold text-slate-800 dark:text-slate-200 truncate flex items-center gap-1.5">
              <span>${this.escapeHtml(h.ip)}</span>
              ${h.hostname ? `<span class="text-slate-400 font-normal truncate">(${this.escapeHtml(h.hostname)})</span>` : ''}
            </div>
            <div class="text-[10px] text-slate-400 flex items-center gap-1.5">
              <span>${this.escapeHtml(h.asset_group_name || 'Global')}</span>
              <span>•</span>
              <span class="text-indigo-600 dark:text-indigo-400 font-medium">${h.vuln_count || 0} vulnerabilidades ativas</span>
            </div>
          </div>
        </div>

        <button type="button" onclick="App.removeWizardHost('${this.escapeHtml(h.ip)}')" class="p-1 rounded-md text-slate-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 cursor-pointer transition shrink-0" title="Remover host do plano">
          <i data-lucide="x" class="w-4 h-4"></i>
        </button>
      </div>
    `).join('');
    this.refreshIcons();
  },

  // --- VULNERABILITY SELECTION (ETAPA 3) ---
  setupWizardStep3View() {
    const hosts = this.state.planWizardSelectedHosts || [];
    const modeWrapper = document.getElementById('plan-wizard-vuln-mode-wrapper');
    const pickerSection = document.getElementById('plan-wizard-vuln-picker-section');
    const pickerLabel = document.getElementById('plan-wizard-vuln-picker-label');
    const contextDesc = document.getElementById('plan-wizard-step3-context-desc');

    const radioAll = document.getElementById('wizard-vuln-mode-all');
    const radioCustom = document.getElementById('wizard-vuln-mode-custom');
    const lblAll = document.getElementById('plan-wizard-mode-label-all');
    const lblCustom = document.getElementById('plan-wizard-mode-label-custom');

    if (hosts.length > 0) {
      if (modeWrapper) modeWrapper.classList.remove('hidden');
      if (contextDesc) {
        contextDesc.textContent = `${hosts.length} asset(s) selecionado(s). Caso nenhuma vulnerabilidade seja selecionada, todas as vulnerabilidades ativas desses assets entrarão no plano.`;
      }
      if (this.state.planWizardVulnMode === 'ALL') {
        if (pickerSection) pickerSection.classList.add('hidden');
        if (radioAll) radioAll.checked = true;
        if (lblAll && lblCustom) {
          lblAll.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/40 cursor-pointer transition';
          lblCustom.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/40 cursor-pointer transition';
        }
      } else {
        if (pickerSection) pickerSection.classList.remove('hidden');
        if (pickerLabel) pickerLabel.textContent = 'Selecione as Vulnerabilidades Específicas';
        if (radioCustom) radioCustom.checked = true;
        if (lblAll && lblCustom) {
          lblCustom.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/40 cursor-pointer transition';
          lblAll.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/40 cursor-pointer transition';
        }
        this.loadWizardCandidateVulns(document.getElementById('plan-wizard-vuln-search')?.value || '');
      }
    } else {
      // Sem hosts: escopo por Vulnerabilidade
      if (modeWrapper) modeWrapper.classList.add('hidden');
      if (pickerSection) pickerSection.classList.remove('hidden');
      if (pickerLabel) pickerLabel.textContent = 'Selecione as Vulnerabilidades Alvo (Plugins)';
      if (contextDesc) {
        contextDesc.textContent = 'Nenhum host específico foi selecionado na Etapa 2. O plano será automaticamente associado a todos os hosts que contêm as vulnerabilidades selecionadas no Grupo de Ativos.';
      }
      this.state.planWizardVulnMode = 'CUSTOM';
      this.loadWizardCandidateVulns(document.getElementById('plan-wizard-vuln-search')?.value || '');
    }
    this.renderWizardSelectedPlugins();
  },

  setWizardVulnMode(mode) {
    this.state.planWizardVulnMode = mode;
    const radioAll = document.getElementById('wizard-vuln-mode-all');
    const radioCustom = document.getElementById('wizard-vuln-mode-custom');
    const lblAll = document.getElementById('plan-wizard-mode-label-all');
    const lblCustom = document.getElementById('plan-wizard-mode-label-custom');

    if (radioAll) radioAll.checked = (mode === 'ALL');
    if (radioCustom) radioCustom.checked = (mode === 'CUSTOM');

    if (lblAll && lblCustom) {
      if (mode === 'ALL') {
        lblAll.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/40 cursor-pointer transition';
        lblCustom.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/40 cursor-pointer transition';
      } else {
        lblCustom.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-indigo-500 bg-indigo-50/50 dark:bg-indigo-950/40 cursor-pointer transition';
        lblAll.className = 'flex items-center gap-2.5 p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-900/40 cursor-pointer transition';
      }
    }

    this.setupWizardStep3View();
    this.updateWizardImpactPreview();
  },

  wizardVulnSearchTimeout: null,
  handleWizardVulnSearch(val) {
    clearTimeout(this.wizardVulnSearchTimeout);
    this.wizardVulnSearchTimeout = setTimeout(() => {
      this.loadWizardCandidateVulns(val);
    }, 250);
  },

  async loadWizardCandidateVulns(search = '') {
    const listEl = document.getElementById('plan-wizard-candidate-vulns');
    if (!listEl) return;

    listEl.innerHTML = `<div class="text-center py-2 text-[11px] text-slate-400"><i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin inline mr-1 text-indigo-500"></i>Buscando vulnerabilidades...</div>`;
    this.refreshIcons();

    try {
      const groupId = document.getElementById('plan-form-asset-group')?.value || '';
      const hosts = this.state.planWizardSelectedHosts || [];
      const hostIps = hosts.map(h => h.ip).join(',');
      const planId = document.getElementById('action-plan-id')?.value || '';

      const vulns = await API.getWizardVulnerabilities(groupId, hostIps, search, planId);
      this.state.planWizardCandidatePlugins = vulns || [];
      this.renderWizardCandidateVulns();
    } catch (err) {
      listEl.innerHTML = `<div class="text-center py-2 text-[11px] text-rose-500">Erro ao buscar vulnerabilidades: ${this.escapeHtml(err.message)}</div>`;
    }
  },

  renderWizardCandidateVulns() {
    const listEl = document.getElementById('plan-wizard-candidate-vulns');
    if (!listEl) return;

    const vulns = this.state.planWizardCandidatePlugins || [];
    if (vulns.length === 0) {
      listEl.innerHTML = `<div class="text-center py-3 text-[11px] text-slate-400">Nenhuma vulnerabilidade ativa encontrada para os critérios selecionados.</div>`;
      return;
    }

    const selectedPids = new Set((this.state.planWizardSelectedPlugins || []).map(p => String(p.plugin_id)));

    listEl.innerHTML = vulns.map(v => {
      const isSelected = selectedPids.has(String(v.plugin_id));
      const pidEscaped = this.escapeHtml(String(v.plugin_id));
      const sevClass = v.severity === 'Critical' ? 'badge-critical' : (v.severity === 'High' ? 'badge-high' : (v.severity === 'Medium' ? 'badge-medium' : 'badge-low'));

      return `
        <div class="flex items-center justify-between p-2 rounded-lg hover:bg-white dark:hover:bg-slate-800/80 transition border ${isSelected ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50/40 dark:bg-emerald-950/20' : 'border-transparent hover:border-slate-200 dark:hover:border-slate-700'} text-[11px]">
          <div class="flex items-center gap-2 min-w-0">
            <span class="${sevClass} px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0">
              ${this.escapeHtml(v.severity)}
            </span>
            <div class="min-w-0">
              <div class="font-bold text-slate-800 dark:text-slate-200 truncate">
                ${this.escapeHtml(v.plugin_name)}
              </div>
              <div class="flex items-center gap-1.5 text-[10px] text-slate-500 dark:text-slate-400 font-mono">
                <span>Plugin #${pidEscaped}</span>
                ${v.cve ? `<span>• ${this.escapeHtml(v.cve)}</span>` : ''}
                <span>•</span>
                <span class="text-indigo-600 dark:text-indigo-400 font-semibold">${v.affected_hosts_count} host(s) afetado(s)</span>
              </div>
            </div>
          </div>

          <button type="button" onclick="App.toggleWizardVulnItem('${pidEscaped}')" class="px-2.5 py-1 rounded-lg text-xs font-semibold cursor-pointer transition shrink-0 ${
            isSelected
              ? 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800'
              : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-xs'
          }">
            ${isSelected ? '✓ Selecionado' : '+ Selecionar'}
          </button>
        </div>
      `;
    }).join('');
    this.refreshIcons();
  },

  toggleWizardVulnItem(pluginId) {
    if (!this.state.planWizardSelectedPlugins) this.state.planWizardSelectedPlugins = [];
    const pidStr = String(pluginId);
    const idx = this.state.planWizardSelectedPlugins.findIndex(p => String(p.plugin_id) === pidStr);

    if (idx >= 0) {
      this.state.planWizardSelectedPlugins.splice(idx, 1);
    } else {
      const candidate = (this.state.planWizardCandidatePlugins || []).find(p => String(p.plugin_id) === pidStr);
      if (candidate) {
        this.state.planWizardSelectedPlugins.push({ ...candidate });
      } else {
        this.state.planWizardSelectedPlugins.push({
          plugin_id: pidStr,
          plugin_name: `Plugin #${pidStr}`,
          severity: 'Medium',
          cve: '',
          affected_hosts_count: 1
        });
      }
    }

    this.renderWizardSelectedPlugins();
    this.renderWizardCandidateVulns();
    this.updateWizardImpactPreview();
  },

  selectAllCandidateVulns() {
    if (!this.state.planWizardSelectedPlugins) this.state.planWizardSelectedPlugins = [];
    const selectedPids = new Set(this.state.planWizardSelectedPlugins.map(p => String(p.plugin_id)));
    const candidates = this.state.planWizardCandidatePlugins || [];
    for (const c of candidates) {
      if (!selectedPids.has(String(c.plugin_id))) {
        this.state.planWizardSelectedPlugins.push({ ...c });
        selectedPids.add(String(c.plugin_id));
      }
    }
    this.renderWizardSelectedPlugins();
    this.renderWizardCandidateVulns();
    this.updateWizardImpactPreview();
  },

  clearSelectedVulns() {
    this.state.planWizardSelectedPlugins = [];
    this.renderWizardSelectedPlugins();
    this.renderWizardCandidateVulns();
    this.updateWizardImpactPreview();
  },

  removeWizardPlugin(pid) {
    if (!this.state.planWizardSelectedPlugins) return;
    this.state.planWizardSelectedPlugins = this.state.planWizardSelectedPlugins.filter(p => String(p.plugin_id) !== String(pid));
    this.renderWizardSelectedPlugins();
    this.renderWizardCandidateVulns();
    this.updateWizardImpactPreview();
  },

  renderWizardSelectedPlugins() {
    const listEl = document.getElementById('plan-wizard-selected-vulns-list');
    const container = document.getElementById('plan-wizard-selected-vulns-container');
    const plugins = this.state.planWizardSelectedPlugins || [];

    if (container) container.classList.toggle('hidden', plugins.length === 0);
    if (!listEl) return;

    listEl.innerHTML = plugins.map(p => `
      <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-950/60 border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300 text-[11px]">
        <span class="font-bold">#${this.escapeHtml(p.plugin_id)}</span>
        <span class="truncate max-w-[150px]">${this.escapeHtml(p.plugin_name)}</span>
        <button type="button" onclick="App.removeWizardPlugin('${this.escapeHtml(p.plugin_id)}')" class="hover:text-rose-500 cursor-pointer ml-0.5">
          <i data-lucide="x" class="w-3.5 h-3.5"></i>
        </button>
      </span>
    `).join('');
    this.refreshIcons();
  },

  // --- IMPACT PREVIEW & RELATIONAL VALIDATION ---
  async updateWizardImpactPreview() {
    const detailsEl = document.getElementById('plan-wizard-impact-details');
    const badgeEl = document.getElementById('plan-wizard-impact-badge');
    const errBox = document.getElementById('action-plan-form-error');
    if (errBox) errBox.classList.add('hidden');

    if (!detailsEl || !badgeEl) return;

    detailsEl.innerHTML = `<div class="py-1 text-slate-400 text-center"><i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin inline mr-1 text-indigo-500"></i>Calculando abrangência e validação relacional...</div>`;
    this.refreshIcons();

    const hosts = this.state.planWizardSelectedHosts || [];
    const plugins = this.state.planWizardSelectedPlugins || [];
    const vulnMode = this.state.planWizardVulnMode || 'ALL';
    const groupId = document.getElementById('plan-form-asset-group')?.value || null;

    let scopeType = 'HOST';
    let targetHostIp = null;
    let targetPluginId = null;
    let scopeHostIps = [];
    let scopePluginIds = [];

    if (hosts.length === 0 && plugins.length > 0) {
      if (plugins.length === 1) {
        scopeType = 'VULNERABILITY';
        targetPluginId = String(plugins[0].plugin_id);
      } else {
        scopeType = 'MATRIX_NN';
        scopeHostIps = [];
        scopePluginIds = plugins.map(p => String(p.plugin_id));
      }
    } else if (hosts.length === 1 && vulnMode === 'ALL') {
      scopeType = 'HOST';
      targetHostIp = hosts[0].ip;
    } else if (hosts.length >= 1 && vulnMode === 'ALL') {
      scopeType = 'MATRIX_NN';
      scopeHostIps = hosts.map(h => h.ip);
      scopePluginIds = [];
    } else if (hosts.length >= 1 && plugins.length > 0) {
      scopeType = 'MATRIX_NN';
      scopeHostIps = hosts.map(h => h.ip);
      scopePluginIds = plugins.map(p => String(p.plugin_id));
    } else {
      badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400';
      badgeEl.textContent = 'Aguardando Seleção';
      detailsEl.innerHTML = `<p class="text-slate-400 text-center py-1">Selecione ao menos um host na Etapa 2 ou uma vulnerabilidade acima para calcular o impacto.</p>`;
      return;
    }

    try {
      const planId = document.getElementById('action-plan-id')?.value || '';
      const res = await API.previewActionPlanImpact({
        scope_type: scopeType,
        asset_group_id: groupId ? parseInt(groupId, 10) : null,
        target_host_ip: targetHostIp,
        target_plugin_id: targetPluginId,
        scope_host_ips: scopeHostIps,
        scope_plugin_ids: scopePluginIds,
        plan_id: planId ? parseInt(planId, 10) : null
      });

      if (!res.is_relational_valid) {
        badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300';
        badgeEl.textContent = 'Escopo Inválido / Não Relacional';

        detailsEl.innerHTML = `
          <div class="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-700 dark:text-rose-300 space-y-1">
            <div class="font-bold flex items-center gap-1">
              <i data-lucide="alert-octagon" class="w-3.5 h-3.5 text-rose-600 dark:text-rose-400"></i>
              <span>Crítica Relacional:</span>
            </div>
            <p class="text-[11px] leading-relaxed font-medium">
              ${this.escapeHtml(res.validation_message || 'Inconsistência relacional entre hosts e plugins informados.')}
            </p>
          </div>
        `;
        this.refreshIcons();
        return;
      }

      badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300';
      badgeEl.textContent = '✓ Relacional Válido (ISO 27001)';

      const sev = res.severity_distribution || {};
      const isHostScope = (scopeType === 'HOST') || (scopeType === 'MATRIX_NN' && (!scopePluginIds || scopePluginIds.length === 0));
      const estTasksCount = isHostScope ? res.unique_hosts_count : res.total_vulnerabilities;
      const tasksScopeLabel = isHostScope ? `${estTasksCount} tarefa(s) (1 por Host)` : `${estTasksCount} tarefa(s) (HOST+VULN)`;

      detailsEl.innerHTML = `
        <div class="space-y-1.5">
          <div class="flex items-center justify-between font-bold text-slate-800 dark:text-slate-200">
            <span>Total de Apontamentos Vinculados:</span>
            <span class="font-mono text-sm text-indigo-600 dark:text-indigo-400">${res.total_vulnerabilities} vulnerabilidades</span>
          </div>
          <div class="flex flex-wrap items-center gap-2 pt-0.5 text-[11px]">
            <span class="badge-critical px-1.5 py-0.5 rounded font-bold">${sev.Critical || 0} Críticas</span>
            <span class="badge-high px-1.5 py-0.5 rounded font-bold">${sev.High || 0} Altas</span>
            <span class="badge-medium px-1.5 py-0.5 rounded font-bold">${sev.Medium || 0} Médias</span>
            <span class="badge-low px-1.5 py-0.5 rounded font-bold">${sev.Low || 0} Baixas</span>
            <span class="text-slate-500 dark:text-slate-400 ml-auto font-mono">${res.unique_hosts_count} host(s) • ${res.unique_plugins_count} plugin(s)</span>
          </div>
          <div class="flex items-center gap-1.5 pt-1 text-[11px]">
            <span class="font-semibold text-slate-700 dark:text-slate-300">Tarefas que serão criadas:</span>
            <span class="px-2 py-0.5 rounded font-bold bg-indigo-100 dark:bg-indigo-950 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800">${tasksScopeLabel}</span>
          </div>
          ${res.already_in_plan_count > 0 ? `
            <div class="text-[10px] text-amber-600 dark:text-amber-400 font-medium flex items-center gap-1 pt-0.5">
              <i data-lucide="info" class="w-3 h-3"></i>
              <span>${res.already_in_plan_count} ocorrência(s) já pertencem a outros planos e serão migradas conforme precedência ISO 27001.</span>
            </div>
          ` : ''}
        </div>
      `;
      this.refreshIcons();
    } catch (err) {
      badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300';
      badgeEl.textContent = 'Erro';
      detailsEl.innerHTML = `<div class="text-rose-500 text-[11px] py-1">Erro ao calcular impacto: ${this.escapeHtml(err.message)}</div>`;
    }
  },

  async openCreatePlanModal(prefill = {}) {
    try {
      await this.populateActionPlanFormSelectors();
    } catch (err) {
      console.warn('Aviso ao popular seletores do plano de ação:', err);
    }

    const modal = document.getElementById('action-plan-modal');
    if (!modal) return;

    // Reset Wizard State
    this.state.planWizardSelectedHosts = [];
    this.state.planWizardSelectedPlugins = [];
    this.state.planWizardVulnMode = 'ALL';
    this.state.planWizardHostOsFilter = '';

    const osSelect = document.getElementById('plan-wizard-host-os-filter');
    if (osSelect) osSelect.value = '';
    const hostSearch = document.getElementById('plan-wizard-host-search');
    if (hostSearch) hostSearch.value = '';

    try {
      document.getElementById('action-plan-modal-title').innerHTML = `
        <i data-lucide="clipboard-check" class="w-5 h-5 text-indigo-600 dark:text-indigo-400"></i>
        <span>Novo Plano de Ação</span>
      `;
      document.getElementById('action-plan-id').value = '';
      document.getElementById('plan-form-title').value = prefill.title || '';
      document.getElementById('plan-form-description').value = prefill.description || '';
      document.getElementById('plan-form-priority').value = prefill.priority || 'HIGH';
      document.getElementById('plan-form-status').value = prefill.status || 'PLANNED';
      document.getElementById('plan-form-due-date').value = prefill.due_date ? prefill.due_date.substring(0, 10) : '';
      document.getElementById('plan-form-autolink').checked = true;

      if (prefill.owner_user_id) {
        this.selectPlanOwner(prefill.owner_user_id);
      } else {
        this.initPlanOwnerDropdown(this.state.user?.id);
      }

      document.getElementById('plan-form-tags').value = Array.isArray(prefill.tags) ? prefill.tags.join(', ') : (prefill.tags || '');

      const groupEl = document.getElementById('plan-form-asset-group');
      if (prefill.asset_group_id) {
        if (groupEl) groupEl.value = String(prefill.asset_group_id);
      } else if (groupEl && (!groupEl.value || groupEl.value === '')) {
        const hierarchical = this.buildHierarchicalGroupList(this.state.assetGroups || []);
        const firstGid = hierarchical.length > 0 ? String(hierarchical[0].id) : (this.state.assetGroups?.[0]?.id ? String(this.state.assetGroups[0].id) : '');
        if (firstGid) groupEl.value = firstGid;
      }

      // Pre-carregamento dinâmico de host
      if (prefill.target_host_ip || prefill.target_host_id) {
        const ip = prefill.target_host_ip || '';
        this.state.planWizardSelectedHosts.push({
          id: prefill.target_host_id || null,
          ip: ip,
          hostname: prefill.target_host_name || '',
          asset_group_id: prefill.asset_group_id || null,
          asset_group_name: '',
          vuln_count: 0
        });
      }

      // Pre-carregamento dinâmico de plugin
      if (prefill.target_plugin_id) {
        this.state.planWizardSelectedPlugins.push({
          plugin_id: String(prefill.target_plugin_id),
          plugin_name: prefill.target_plugin_name || `Plugin #${prefill.target_plugin_id}`,
          severity: prefill.priority || 'High',
          cve: '',
          affected_hosts_count: 1
        });
        this.state.planWizardVulnMode = 'CUSTOM';
      }

      const autolinkWrapper = document.getElementById('plan-form-autolink-wrapper');
      if (autolinkWrapper) autolinkWrapper.classList.remove('hidden');

      const errBox = document.getElementById('action-plan-form-error');
      if (errBox) errBox.classList.add('hidden');
    } catch (err) {
      console.warn('Erro ao configurar campos do plano de ação:', err);
    }

    modal.classList.remove('hidden');
    this.goToPlanWizardStep(1);
    this.refreshIcons();
  },

  async openCreatePlanModalFromHost() {
    const host = this.state.inventoryCurrentHost;
    const ip = host?.ip_address || host?.ip || document.getElementById('host-modal-ip')?.textContent?.trim() || '';
    const name = host?.hostname || document.getElementById('host-modal-name')?.textContent?.trim() || '';
    
    this.closeHostModal();
    this.navigate('actionPlans');
    try {
      await this.openCreatePlanModal({
        scope_type: 'HOST',
        target_host_id: host?.id || null,
        target_host_ip: ip || null,
        target_host_name: name || null,
        asset_group_id: host?.asset_group_id || null,
        title: `Plano de Remediação - Host ${ip}${name && name !== 'Sem hostname' && name !== '-' ? ` (${name})` : ''}`,
        description: `Iniciativa de remediação e conformidade cibernética para o ativo ${ip}.`,
        priority: 'HIGH'
      });
    } catch (e) {
      console.error('Erro ao abrir plano do host:', e);
    }
  },

  async openCreatePlanModalFromVuln() {
    const v = this.state.currentVulnModalData;
    const tStatus = (v?.treatment_status || '').toLowerCase();
    if (tStatus === 'remediated') {
      alert('Esta vulnerabilidade já está remediada e não requer plano de ação.');
      return;
    }
    if (tStatus && tStatus !== 'open') {
      alert(`Vulnerabilidade com status "${v?.treatment_status || ''}". Apenas vulnerabilidades com status "Open" são elegíveis para a criação de um plano de ação.`);
      return;
    }

    const pluginId = v?.plugin_id || '';
    const title = v?.plugin_name || document.getElementById('modal-vuln-title')?.textContent?.trim() || 'Vulnerabilidade';
    
    this.closeVulnDetailsModal();
    this.navigate('actionPlans');
    try {
      await this.openCreatePlanModal({
        scope_type: 'VULNERABILITY',
        target_plugin_id: pluginId,
        target_plugin_name: title,
        target_host_id: v?.host_id || null,
        target_host_ip: v?.host_ip || null,
        target_host_name: v?.host_name || null,
        asset_group_id: v?.asset_group_id || null,
        title: `Plano de Remediação: ${title.substring(0, 100)}`,
        description: `Remediação técnica da vulnerabilidade (Plugin ID: ${pluginId}).`,
        priority: (v?.severity || 'HIGH').toUpperCase()
      });
    } catch (e) {
      console.error('Erro ao abrir plano da vulnerabilidade:', e);
    }
  },

  async openCreatePlanModalFromPlugin() {
    const pluginId = document.getElementById('plugin-modal-id')?.textContent?.trim();
    const title = document.getElementById('plugin-modal-title')?.textContent?.trim() || 'Plugin Nessus';
    
    this.closePluginSolutionModal();
    this.navigate('actionPlans');
    try {
      await this.openCreatePlanModal({
        scope_type: 'VULNERABILITY',
        target_plugin_id: pluginId,
        target_plugin_name: title,
        title: `Plano de Correção: ${title.substring(0, 100)}`,
        description: `Execução do plano de correção técnica para o Plugin ID ${pluginId}.`,
        priority: 'HIGH'
      });
    } catch (e) {
      console.error('Erro ao abrir plano do plugin:', e);
    }
  },

  async openEditPlanModal(planId) {
    await this.populateActionPlanFormSelectors();
    const modal = document.getElementById('action-plan-modal');
    if (!modal) return;

    try {
      const p = await API.getActionPlan(planId);
      document.getElementById('action-plan-modal-title').innerHTML = `
        <i data-lucide="edit-3" class="w-5 h-5 text-indigo-600 dark:text-indigo-400"></i>
        <span>Editar Plano de Ação #${p.id}</span>
      `;
      document.getElementById('action-plan-id').value = p.id;
      document.getElementById('plan-form-title').value = p.title || '';
      document.getElementById('plan-form-description').value = p.description || '';

      if (p.asset_group_id) {
        document.getElementById('plan-form-asset-group').value = String(p.asset_group_id);
      }

      document.getElementById('plan-form-tags').value = (p.tags || []).map(t => t.name || t).join(', ');
      document.getElementById('plan-form-priority').value = p.priority || 'HIGH';
      document.getElementById('plan-form-status').value = p.status || 'PLANNED';
      if (p.owner_user_id) {
        document.getElementById('plan-form-owner').value = String(p.owner_user_id);
        this.selectPlanOwner(p.owner_user_id);
      } else {
        this.initPlanOwnerDropdown();
      }
      document.getElementById('plan-form-due-date').value = p.due_date ? p.due_date.substring(0, 10) : '';

      this.state.planWizardHostOsFilter = '';
      const osSelect = document.getElementById('plan-wizard-host-os-filter');
      if (osSelect) osSelect.value = '';
      const hostSearch = document.getElementById('plan-wizard-host-search');
      if (hostSearch) hostSearch.value = '';

      // Populate wizard hosts
      this.state.planWizardSelectedHosts = [];
      if (p.scope_type === 'HOST' && (p.target_host_ip || p.target_host_id)) {
        this.state.planWizardSelectedHosts.push({
          id: p.target_host_id,
          ip: p.target_host_ip || `Host #${p.target_host_id}`,
          hostname: p.target_host_name || '',
          asset_group_name: p.asset_group_name || 'Global',
          vuln_count: 0
        });
      } else if (p.scope_host_ips && p.scope_host_ips.length > 0) {
        this.state.planWizardSelectedHosts = p.scope_host_ips.map(ip => ({
          id: null,
          ip: ip,
          hostname: '',
          asset_group_name: p.asset_group_name || 'Global',
          vuln_count: 0
        }));
      }

      // Populate wizard plugins
      this.state.planWizardSelectedPlugins = [];
      if (p.scope_type === 'VULNERABILITY' && p.target_plugin_id) {
        this.state.planWizardSelectedPlugins.push({
          plugin_id: String(p.target_plugin_id),
          plugin_name: `Plugin #${p.target_plugin_id}`,
          severity: 'High',
          cve: '',
          affected_hosts_count: 1
        });
        this.state.planWizardVulnMode = 'CUSTOM';
      } else if (p.scope_plugin_ids && p.scope_plugin_ids.length > 0) {
        this.state.planWizardSelectedPlugins = p.scope_plugin_ids.map(pid => ({
          plugin_id: String(pid),
          plugin_name: `Plugin #${pid}`,
          severity: 'High',
          cve: '',
          affected_hosts_count: 1
        }));
        this.state.planWizardVulnMode = 'CUSTOM';
      } else {
        this.state.planWizardVulnMode = 'ALL';
      }

      // Disable autolink on edit
      const autolinkWrapper = document.getElementById('plan-form-autolink-wrapper');
      if (autolinkWrapper) autolinkWrapper.classList.add('hidden');

      const errBox = document.getElementById('action-plan-form-error');
      if (errBox) errBox.classList.add('hidden');

      modal.classList.remove('hidden');
      this.goToPlanWizardStep(1);
      this.refreshIcons();
    } catch (err) {
      alert(`Erro ao abrir plano para edição: ${err.message}`);
    }
  },

  closeActionPlanModal() {
    this.closePlanOwnerDropdown();
    const modal = document.getElementById('action-plan-modal');
    if (modal) modal.classList.add('hidden');
  },

  async handleSaveActionPlan(e) {
    e.preventDefault();
    const btn = document.getElementById('btn-save-action-plan');
    const errBox = document.getElementById('action-plan-form-error');
    if (errBox) errBox.classList.add('hidden');

    const planId = document.getElementById('action-plan-id')?.value;
    const title = document.getElementById('plan-form-title')?.value.trim();
    const description = document.getElementById('plan-form-description')?.value.trim();
    const assetGroupId = document.getElementById('plan-form-asset-group')?.value;
    const priority = document.getElementById('plan-form-priority')?.value || 'HIGH';
    const status = document.getElementById('plan-form-status')?.value || 'PLANNED';
    const ownerId = document.getElementById('plan-form-owner')?.value;
    const dueDate = document.getElementById('plan-form-due-date')?.value;
    const autoLink = document.getElementById('plan-form-autolink')?.checked;

    const tagStr = document.getElementById('plan-form-tags')?.value || '';
    const tags = tagStr.split(',').map(s => s.trim()).filter(Boolean);

    if (!title) {
      this.goToPlanWizardStep(1);
      if (errBox) {
        errBox.textContent = 'O título do plano de ação é obrigatório.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    const hosts = this.state.planWizardSelectedHosts || [];
    const plugins = this.state.planWizardSelectedPlugins || [];
    const vulnMode = this.state.planWizardVulnMode || 'ALL';

    if (hosts.length === 0 && plugins.length === 0) {
      this.goToPlanWizardStep(2);
      if (errBox) {
        errBox.textContent = 'Selecione ao menos um host na Etapa 2 ou uma vulnerabilidade na Etapa 3.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    let scopeType = 'HOST';
    let targetHostIdNum = null;
    let targetHostIpStr = null;
    let targetPluginIdStr = null;
    let scopeHostIps = [];
    let scopePluginIds = [];

    if (hosts.length === 0 && plugins.length > 0) {
      if (plugins.length === 1) {
        scopeType = 'VULNERABILITY';
        targetPluginIdStr = String(plugins[0].plugin_id);
      } else {
        scopeType = 'MATRIX_NN';
        scopeHostIps = [];
        scopePluginIds = plugins.map(p => String(p.plugin_id));
      }
    } else if (hosts.length === 1 && vulnMode === 'ALL') {
      scopeType = 'HOST';
      targetHostIpStr = hosts[0].ip;
      targetHostIdNum = hosts[0].id || null;
    } else if (hosts.length >= 1 && vulnMode === 'ALL') {
      scopeType = 'MATRIX_NN';
      scopeHostIps = hosts.map(h => h.ip);
      scopePluginIds = [];
    } else if (hosts.length >= 1 && plugins.length > 0) {
      scopeType = 'MATRIX_NN';
      scopeHostIps = hosts.map(h => h.ip);
      scopePluginIds = plugins.map(p => String(p.plugin_id));
    }

    const payload = {
      title,
      description: description || null,
      scope_type: scopeType,
      asset_group_id: assetGroupId ? parseInt(assetGroupId, 10) : null,
      target_host_id: targetHostIdNum,
      target_host_ip: targetHostIpStr,
      target_plugin_id: targetPluginIdStr,
      tags,
      scope_host_ips: scopeHostIps,
      scope_plugin_ids: scopePluginIds,
      priority,
      status,
      owner_user_id: ownerId ? parseInt(ownerId, 10) : null,
      due_date: dueDate ? `${dueDate}T23:59:59` : null,
      auto_link_vulnerabilities: planId ? false : !!autoLink
    };

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Salvando...';
    }

    try {
      if (planId) {
        await API.updateActionPlan(parseInt(planId, 10), payload);
      } else {
        await API.createActionPlan(payload);
      }
      this.closeActionPlanModal();
      this.loadActionPlansData();
    } catch (err) {
      console.error('Erro ao salvar plano de ação:', err);
      if (errBox) {
        errBox.textContent = `Erro ao salvar plano: ${err.message}`;
        errBox.classList.remove('hidden');
        errBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Finalizar plano de ação';
      }
    }
  },

  async openActionPlanDetail(planId) {
    const modal = document.getElementById('action-plan-detail-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    // Loading State
    document.getElementById('plan-detail-title').textContent = 'Carregando plano...';
    document.getElementById('plan-detail-tasks-list').innerHTML = `
      <div class="text-center py-8 text-slate-400">
        <i data-lucide="loader-2" class="w-5 h-5 animate-spin mx-auto text-indigo-500 mb-1"></i>
        <span>Carregando etapas técnicas...</span>
      </div>
    `;
    this.refreshIcons();

    try {
      const p = await API.getActionPlan(planId);
      this.state.currentActionPlan = p;

      document.getElementById('plan-detail-id-badge').textContent = `#${p.id}`;
      document.getElementById('plan-detail-title').textContent = p.title || 'Plano sem título';
      document.getElementById('plan-detail-scope-badge').textContent = `ESCOPO: ${p.scope_type || 'CUSTOM'}`;

      // Priority badge
      const prioBadge = document.getElementById('plan-detail-priority-badge');
      if (prioBadge) {
        prioBadge.innerHTML = this.getActionPlanPriorityBadge(p.priority);
      }

      // Status badge
      const stBadge = document.getElementById('plan-detail-status-badge');
      if (stBadge) {
        stBadge.innerHTML = this.getActionPlanStatusBadge(p.status);
      }

      // Overdue badge
      const odBadge = document.getElementById('plan-detail-overdue-badge');
      if (odBadge) {
        if (p.is_overdue) odBadge.classList.remove('hidden');
        else odBadge.classList.add('hidden');
      }

      // Metadata
      document.getElementById('plan-detail-group').textContent = p.asset_group_name || 'Global (Todos)';
      
      let targetText = '-';
      if (p.scope_type === 'HOST') targetText = p.target_host_ip ? `${p.target_host_ip}${p.target_host_name ? ` (${p.target_host_name})` : ''}` : '-';
      else if (p.scope_type === 'VULNERABILITY') targetText = p.target_plugin_id ? `Plugin ID #${p.target_plugin_id}` : '-';
      else if (p.scope_type === 'MATRIX_NN') targetText = `Matriz: ${(p.scope_host_ips || []).join(', ') || 'Nenhum host'} × Plugins: ${(p.scope_plugin_ids || []).join(', ') || 'Nenhum'}`;
      else if (p.scope_type === 'GROUP') targetText = p.asset_group_name || '-';
      document.getElementById('plan-detail-target').textContent = targetText;

      const tagsContainer = document.getElementById('plan-detail-tags-container');
      if (tagsContainer) {
        if (p.tags && p.tags.length > 0) {
          tagsContainer.innerHTML = p.tags.map(t => `<span class="px-2 py-0.5 rounded text-[10px] font-semibold" style="background-color: ${(t.color || '#6366f1')}20; color: ${t.color || '#6366f1'}; border: 1px solid ${(t.color || '#6366f1')}40;">${this.escapeHtml(t.name || t)}</span>`).join('');
        } else {
          tagsContainer.innerHTML = '';
        }
      }

      document.getElementById('plan-detail-owner').textContent = p.owner_user_name || '-';
      document.getElementById('plan-detail-due').textContent = p.due_date ? new Date(p.due_date).toLocaleDateString('pt-BR') : 'Sem prazo fixado';

      // Description
      const descEl = document.getElementById('plan-detail-description');
      const descContainer = document.getElementById('plan-detail-description-container');
      if (p.description) {
        descEl.textContent = p.description;
        descContainer.classList.remove('hidden');
      } else {
        descContainer.classList.add('hidden');
      }

      // Progress bar
      const pct = p.progress_percent || 0;
      document.getElementById('plan-detail-progress-badge').textContent = `${pct.toFixed(0)}%`;
      document.getElementById('plan-detail-progress-bar').style.width = `${pct}%`;
      document.getElementById('plan-detail-tasks-ratio').textContent = `${p.completed_tasks} de ${p.total_tasks} etapas concluídas`;
      document.getElementById('plan-detail-created-info').textContent = `Criado em: ${new Date(p.created_at).toLocaleString('pt-BR')}`;

      // Tasks List
      const tasksListEl = document.getElementById('plan-detail-tasks-list');
      const noTasksEl = document.getElementById('plan-detail-no-tasks');
      const countEl = document.getElementById('plan-detail-tasks-count');
      const tasks = p.tasks || [];

      if (countEl) countEl.textContent = tasks.length;

      if (tasks.length === 0) {
        tasksListEl.innerHTML = '';
        if (noTasksEl) noTasksEl.classList.remove('hidden');
      } else {
        if (noTasksEl) noTasksEl.classList.add('hidden');
        tasksListEl.innerHTML = tasks.map((t, idx) => {
          const tDue = t.due_date ? new Date(t.due_date).toLocaleDateString('pt-BR') : '-';
          const isDone = t.status === 'DONE';
          return `
            <div class="p-3.5 rounded-xl border ${isDone ? 'bg-emerald-50/30 dark:bg-emerald-950/20 border-emerald-200/60 dark:border-emerald-900/40' : 'bg-slate-50 dark:bg-slate-900/80 border-slate-200 dark:border-slate-800'} shadow-xs space-y-2">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center space-x-2 min-w-0">
                  <span class="w-5 h-5 rounded-full flex items-center justify-center bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-mono text-[10px] font-bold">
                    ${idx + 1}
                  </span>
                  <h5 class="font-bold text-xs text-slate-900 dark:text-slate-100 flex items-center gap-1.5 ${isDone ? 'line-through text-slate-500' : ''}">
                    <i data-lucide="server" class="w-3.5 h-3.5 text-indigo-500 shrink-0"></i>
                    <span>${this.escapeHtml(t.title)}</span>
                  </h5>
                </div>
                <div class="flex items-center space-x-1.5">
                  <!-- Quick Status Dropdown -->
                  <select onchange="App.quickUpdateTaskStatus(${t.id}, this.value)" class="text-[11px] px-2 py-1 rounded-lg font-semibold bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 focus:outline-none focus:ring-1 focus:ring-indigo-500 cursor-pointer">
                    <option value="TODO" ${t.status === 'TODO' ? 'selected' : ''}>A Fazer (TODO)</option>
                    <option value="DOING" ${t.status === 'DOING' ? 'selected' : ''}>Em Execução (DOING)</option>
                    <option value="REVIEW" ${t.status === 'REVIEW' ? 'selected' : ''}>Em Revisão (REVIEW)</option>
                    <option value="DONE" ${t.status === 'DONE' ? 'selected' : ''}>Concluído (DONE)</option>
                    <option value="BLOCKED" ${t.status === 'BLOCKED' ? 'selected' : ''}>Bloqueado (BLOCKED)</option>
                  </select>
                  <button onclick="App.openEditTaskModal(${t.id})" class="p-1 rounded text-slate-400 hover:text-slate-700 dark:hover:text-white cursor-pointer" title="Editar Etapa">
                    <i data-lucide="edit-2" class="w-3.5 h-3.5"></i>
                  </button>
                  <button onclick="App.deleteTask(${t.id})" class="p-1 rounded text-rose-400 hover:text-rose-600 cursor-pointer" title="Excluir Etapa">
                    <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                  </button>
                </div>
              </div>

              ${t.description ? `
                <div class="p-2 rounded-lg bg-slate-100/70 dark:bg-slate-800/60 border border-slate-200/60 dark:border-slate-700/50 space-y-1">
                  <div class="text-[10px] uppercase font-bold text-slate-400 dark:text-slate-500">Vulnerabilidade(s) Alvo:</div>
                  <p class="text-[11px] text-slate-700 dark:text-slate-300 whitespace-pre-line font-medium leading-relaxed">${this.escapeHtml(t.description)}</p>
                </div>
              ` : ''}

              ${t.vulnerability_links && t.vulnerability_links.length > 0 ? `
                <div class="flex flex-wrap items-center gap-1.5 pt-0.5">
                  ${t.vulnerability_links.slice(0, 4).map(vl => {
                    const sevClass = (vl.severity || '').toLowerCase() === 'critical' ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30' :
                                     (vl.severity || '').toLowerCase() === 'high' ? 'bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30' :
                                     (vl.severity || '').toLowerCase() === 'medium' ? 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30' :
                                     'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
                    return `
                      <button type="button" onclick="App.openVulnDetailsModal(${vl.vulnerability_id})" class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-white dark:bg-slate-800 border ${sevClass} hover:ring-1 hover:ring-indigo-400 transition cursor-pointer" title="Clique para ver os detalhes da vulnerabilidade #${vl.plugin_id}">
                        <span class="font-bold">#${vl.plugin_id}</span>
                        ${vl.severity ? `<span class="font-semibold text-[9px] uppercase">${vl.severity}</span>` : ''}
                        <i data-lucide="external-link" class="w-2.5 h-2.5 opacity-60"></i>
                      </button>
                    `;
                  }).join('')}
                  ${t.vulnerability_links.length > 4 ? `
                    <span class="text-[10px] text-slate-400 font-semibold">+${t.vulnerability_links.length - 4} mais</span>
                  ` : ''}
                </div>
              ` : ''}

              <div class="flex flex-wrap items-center justify-between gap-2 pt-1 border-t border-slate-100 dark:border-slate-800/60 text-[11px] text-slate-500 dark:text-slate-400">
                <div class="flex items-center space-x-3">
                  <span>
                    <i data-lucide="user" class="w-3 h-3 inline mr-1 text-slate-400"></i>
                    <strong>${this.escapeHtml(t.assigned_user_name || 'Não atribuído')}</strong>
                  </span>
                  <span class="${t.is_overdue ? 'text-rose-500 font-bold' : ''}">
                    <i data-lucide="calendar" class="w-3 h-3 inline mr-1 text-slate-400"></i>
                    Prazo: ${tDue} ${t.is_overdue ? '(Atrasado)' : ''}
                  </span>
                </div>
                ${t.vulnerabilities_count > 0 ? `
                  <span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 text-[10px] font-semibold">
                    <i data-lucide="shield" class="w-3 h-3"></i>
                    <span>${t.vulnerabilities_count} vulnerabilidade(s) vinculada(s)</span>
                  </span>
                ` : ''}
              </div>
            </div>
          `;
        }).join('');
      }

      this.refreshIcons();
    } catch (err) {
      console.error('Erro ao abrir detalhes do plano:', err);
      alert(`Erro ao abrir detalhes do plano: ${err.message}`);
    }
  },

  closeActionPlanDetailModal() {
    const modal = document.getElementById('action-plan-detail-modal');
    if (modal) modal.classList.add('hidden');
  },

  editCurrentPlan() {
    if (!this.state.currentActionPlan) return;
    const planId = this.state.currentActionPlan.id;
    this.closeActionPlanDetailModal();
    this.openEditPlanModal(planId);
  },

  deleteCurrentPlan() {
    if (!this.state.currentActionPlan) return;
    this.handleDeletePlan(this.state.currentActionPlan.id);
  },

  async handleDeletePlan(planId) {
    if (!confirm(`Tem certeza que deseja excluir o Plano de Ação #${planId}? Todas as suas etapas associadas serão removidas.`)) {
      return;
    }
    try {
      await API.deleteActionPlan(planId);
      this.closeActionPlanDetailModal();
      this.loadActionPlansData();
    } catch (err) {
      alert(`Erro ao excluir plano de ação: ${err.message}`);
    }
  },

  // Task Operations
  async openCreateTaskModal() {
    if (!this.state.currentActionPlan) return;
    await this.populateActionPlanFormSelectors();

    const modal = document.getElementById('action-task-modal');
    if (!modal) return;

    document.getElementById('action-task-modal-title').innerHTML = `
      <i data-lucide="list-checks" class="w-5 h-5 text-indigo-600 dark:text-indigo-400"></i>
      <span>Nova Etapa Técnica</span>
    `;
    document.getElementById('action-task-id').value = '';
    document.getElementById('action-task-plan-id').value = this.state.currentActionPlan.id;
    document.getElementById('task-form-title').value = '';
    document.getElementById('task-form-description').value = '';
    document.getElementById('task-form-status').value = 'TODO';
    document.getElementById('task-form-start-date').value = '';
    document.getElementById('task-form-due-date').value = this.state.currentActionPlan.due_date ? this.state.currentActionPlan.due_date.substring(0, 10) : '';
    document.getElementById('task-form-sync-vulns').checked = true;

    const errBox = document.getElementById('action-task-form-error');
    if (errBox) errBox.classList.add('hidden');

    modal.classList.remove('hidden');
    this.refreshIcons();
  },

  async openEditTaskModal(taskId) {
    if (!this.state.currentActionPlan) return;
    await this.populateActionPlanFormSelectors();

    const task = (this.state.currentActionPlan.tasks || []).find(t => t.id === taskId);
    if (!task) return;

    const modal = document.getElementById('action-task-modal');
    if (!modal) return;

    document.getElementById('action-task-modal-title').innerHTML = `
      <i data-lucide="edit-3" class="w-5 h-5 text-indigo-600 dark:text-indigo-400"></i>
      <span>Editar Etapa #${task.id}</span>
    `;
    document.getElementById('action-task-id').value = task.id;
    document.getElementById('action-task-plan-id').value = this.state.currentActionPlan.id;
    document.getElementById('task-form-title').value = task.title || '';
    document.getElementById('task-form-description').value = task.description || '';
    document.getElementById('task-form-status').value = task.status || 'TODO';
    if (task.assigned_user_id) {
      document.getElementById('task-form-assignee').value = String(task.assigned_user_id);
    }
    document.getElementById('task-form-start-date').value = task.start_date ? task.start_date.substring(0, 10) : '';
    document.getElementById('task-form-due-date').value = task.due_date ? task.due_date.substring(0, 10) : '';
    document.getElementById('task-form-sync-vulns').checked = true;

    const errBox = document.getElementById('action-task-form-error');
    if (errBox) errBox.classList.add('hidden');

    modal.classList.remove('hidden');
    this.refreshIcons();
  },

  closeActionTaskModal() {
    const modal = document.getElementById('action-task-modal');
    if (modal) modal.classList.add('hidden');
  },

  async handleSaveActionTask(e) {
    e.preventDefault();
    const btn = document.getElementById('btn-save-action-task');
    const errBox = document.getElementById('action-task-form-error');
    if (errBox) errBox.classList.add('hidden');

    const taskId = document.getElementById('action-task-id')?.value;
    const planId = parseInt(document.getElementById('action-task-plan-id')?.value || this.state.currentActionPlan?.id);
    const title = document.getElementById('task-form-title')?.value.trim();
    const description = document.getElementById('task-form-description')?.value.trim();
    const status = document.getElementById('task-form-status')?.value;
    const assigneeId = document.getElementById('task-form-assignee')?.value;
    const startDate = document.getElementById('task-form-start-date')?.value;
    const dueDate = document.getElementById('task-form-due-date')?.value;
    const syncVulns = document.getElementById('task-form-sync-vulns')?.checked;

    if (!title) {
      if (errBox) {
        errBox.textContent = 'O título da etapa é obrigatório.';
        errBox.classList.remove('hidden');
      }
      return;
    }

    const payload = {
      title,
      description: description || null,
      status,
      assigned_user_id: assigneeId ? parseInt(assigneeId) : null,
      start_date: startDate ? `${startDate}T00:00:00` : null,
      due_date: dueDate ? `${dueDate}T23:59:59` : null,
      sync_vuln_treatment: !!syncVulns
    };

    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Salvando...';
    }

    try {
      if (taskId) {
        await API.updateActionTask(parseInt(taskId), payload);
      } else {
        await API.addActionTask(planId, payload);
      }
      this.closeActionTaskModal();
      await this.openActionPlanDetail(planId);
      this.loadActionPlansData();
    } catch (err) {
      console.error('Erro ao salvar etapa:', err);
      if (errBox) {
        errBox.textContent = `Erro ao salvar etapa: ${err.message}`;
        errBox.classList.remove('hidden');
      }
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Salvar Etapa';
      }
    }
  },

  async quickUpdateTaskStatus(taskId, status) {
    try {
      await API.updateActionTask(taskId, {
        status,
        sync_vuln_treatment: true
      });
      if (this.state.currentActionPlan) {
        await this.openActionPlanDetail(this.state.currentActionPlan.id);
      }
      this.loadActionPlansData();
    } catch (err) {
      alert(`Erro ao atualizar status da etapa: ${err.message}`);
    }
  },

  async deleteTask(taskId) {
    if (!confirm('Deseja realmente excluir esta etapa técnica?')) {
      return;
    }
    try {
      await API.deleteActionTask(taskId);
      if (this.state.currentActionPlan) {
        await this.openActionPlanDetail(this.state.currentActionPlan.id);
      }
      this.loadActionPlansData();
    } catch (err) {
      alert(`Erro ao remover etapa: ${err.message}`);
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
