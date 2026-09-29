/**
 * GvulStand API Client
 */
const API_BASE = '/api';

const API = {
  // Auth Token helpers
  getToken() {
    return localStorage.getItem('gvul_token');
  },
  setToken(token) {
    localStorage.setItem('gvul_token', token);
  },
  getUser() {
    const userStr = localStorage.getItem('gvul_user');
    return userStr ? JSON.parse(userStr) : null;
  },
  setUser(user) {
    localStorage.setItem('gvul_user', JSON.stringify(user));
  },
  clearSession() {
    localStorage.removeItem('gvul_token');
    localStorage.removeItem('gvul_user');
  },

  async request(endpoint, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const config = {
      ...options,
      headers
    };

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, config);

      if (res.status === 401) {
        if (!endpoint.startsWith('/auth/login')) {
          this.clearSession();
          window.dispatchEvent(new CustomEvent('auth-required'));
          throw new Error('Sessão expirada. Faça login novamente.');
        }
      }

      if (res.status === 204) {
        return null;
      }

      let data;
      const contentType = res.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        try {
          data = await res.json();
        } catch {
          const text = await res.text();
          data = { detail: text };
        }
      } else {
        const text = await res.text();
        data = { detail: text || `Erro HTTP ${res.status}` };
      }

      if (!res.ok) {
        let msg = data.detail || data.message || `Erro na requisição (Status ${res.status})`;
        if (Array.isArray(msg)) {
          msg = msg.map(item => (typeof item === 'object' && item.msg ? `${(item.loc || []).slice(1).join('.')}: ${item.msg}` : String(item))).join('; ');
        }
        throw new Error(msg);
      }
      return data;
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  // Auth Endpoints
  async login(username, password) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    this.setToken(data.access_token);
    this.setUser(data.user);
    return data;
  },

  async getMe() {
    return this.request('/auth/me');
  },

  async changePassword(old_password, new_password) {
    return this.request('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ old_password, new_password })
    });
  },

  // Users Endpoints
  async listUsers() {
    return this.request('/users');
  },
  async createUser(userData) {
    return this.request('/users', {
      method: 'POST',
      body: JSON.stringify(userData)
    });
  },
  async updateUser(userId, userData) {
    return this.request(`/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify(userData)
    });
  },
  async deleteUser(userId) {
    return this.request(`/users/${userId}`, {
      method: 'DELETE'
    });
  },

  // LDAP / Active Directory Endpoints
  async getLdapConfig() {
    return this.request('/ldap/config');
  },
  async updateLdapConfig(configData) {
    return this.request('/ldap/config', {
      method: 'PUT',
      body: JSON.stringify(configData)
    });
  },
  async testLdapConnection(testData) {
    return this.request('/ldap/test', {
      method: 'POST',
      body: JSON.stringify(testData)
    });
  },
  async validateLdapUser(samAccountName) {
    return this.request(`/ldap/validate-user?sam_account_name=${encodeURIComponent(samAccountName)}`);
  },

  // System Parameters Endpoints
  async getParameters() {
    return this.request('/parameters');
  },
  async updateParameters(paramsData) {
    return this.request('/parameters', {
      method: 'PUT',
      body: JSON.stringify(paramsData)
    });
  },
  async getTimezones() {
    return this.request('/parameters/timezones');
  },
  async previewIgnoredVulnerabilities(ignoredIds) {
    return this.request('/parameters/preview-ignored', {
      method: 'POST',
      body: JSON.stringify({ ignored_ids: ignoredIds })
    });
  },
  async applySlasToAllGroups() {
    return this.request('/parameters/apply-slas-to-all-groups', {
      method: 'POST'
    });
  },

  // Asset Groups Endpoints
  async listAssetGroups() {
    return this.request('/asset-groups');
  },
  async createAssetGroup(groupData) {
    return this.request('/asset-groups', {
      method: 'POST',
      body: JSON.stringify(groupData)
    });
  },
  async updateAssetGroup(groupId, groupData) {
    return this.request(`/asset-groups/${groupId}`, {
      method: 'PUT',
      body: JSON.stringify(groupData)
    });
  },
  async deleteAssetGroup(groupId) {
    return this.request(`/asset-groups/${groupId}`, {
      method: 'DELETE'
    });
  },

  // Scans Endpoints
  async listScans(assetGroupId = null, scanType = null) {
    let query = [];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    if (scanType) query.push(`scan_type=${scanType}`);
    const qs = query.length ? `?${query.join('&')}` : '';
    return this.request(`/scans${qs}`);
  },

  async uploadScan(formData) {
    return this.request('/scans/upload', {
      method: 'POST',
      body: formData
    });
  },

  async getScan(scanId) {
    return this.request(`/scans/${scanId}`);
  },

  async deleteScan(scanId) {
    return this.request(`/scans/${scanId}`, {
      method: 'DELETE'
    });
  },

  // Dashboard & Governance Endpoints
  async getDashboardStats(assetGroupId = null) {
    const qs = assetGroupId ? `?asset_group_id=${assetGroupId}` : '';
    return this.request(`/dashboard/stats${qs}`);
  },

  async getTopCritical(assetGroupId = null, limit = 100) {
    let query = [`limit=${limit}`];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    return this.request(`/dashboard/top-critical?${query.join('&')}`);
  },

  async getTopExploits(assetGroupId = null, limit = 20) {
    let query = [`limit=${limit}`];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    return this.request(`/dashboard/top-hosts-exploits?${query.join('&')}`);
  },

  async getPluginSolution(pluginId, assetGroupId = null) {
    let query = [];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    const qs = query.length ? `?${query.join('&')}` : '';
    return this.request(`/dashboard/plugin-solution/${encodeURIComponent(pluginId)}${qs}`);
  },

  async getScanDiagnostics(assetGroupId = null, category = null) {
    let query = [];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    if (category) query.push(`category=${encodeURIComponent(category)}`);
    const qs = query.length ? `?${query.join('&')}` : '';
    return this.request(`/dashboard/scan-diagnostics${qs}`);
  },

  // Comparative Diff Endpoints (ISO 9001 PDCA)
  async getComparativeDiff(baselineScanId, retestScanId) {
    return this.request(`/comparative/diff?baseline_scan_id=${baselineScanId}&retest_scan_id=${retestScanId}`);
  },

  async getScansByGroup(assetGroupId) {
    return this.request(`/comparative/scans-by-group/${assetGroupId}`);
  },

  // Executive Reports Endpoints
  async getReportTemplates() {
    return this.request('/reports/templates');
  },

  async getExecutiveSummaryReport(params = {}) {
    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        query.append(k, v);
      }
    }
    return this.request(`/reports/summary-data?${query.toString()}`);
  },

  // Scans Endpoints
  async listScans(assetGroupId = null, scanType = null) {
    let query = [];
    if (assetGroupId) query.push(`asset_group_id=${assetGroupId}`);
    if (scanType) query.push(`scan_type=${scanType}`);
    const qs = query.length ? `?${query.join('&')}` : '';
    return this.request(`/scans${qs}`);
  },

  async uploadScan(formData) {
    return this.request('/scans/upload', {
      method: 'POST',
      body: formData
    });
  },

  async deleteScan(scanId) {
    return this.request(`/scans/${scanId}`, {
      method: 'DELETE'
    });
  },

  // Vulnerability & Host Endpoints
  async listVulnerabilities(params = {}) {
    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        query.append(k, v);
      }
    }
    return this.request(`/vulnerabilities?${query.toString()}`);
  },

  async getVulnerability(vulnId) {
    return this.request(`/vulnerabilities/${vulnId}`);
  },

  async getUniqueHosts(assetGroupId = '') {
    const query = assetGroupId ? `?asset_group_id=${assetGroupId}` : '';
    return this.request(`/vulnerabilities/unique-hosts${query}`);
  },

  async listInventory(params = {}) {
    const query = new URLSearchParams();
    if (params.asset_group_id) query.append('asset_group_id', params.asset_group_id);
    if (params.search) query.append('search', params.search);
    if (params.severity_filter) query.append('severity_filter', params.severity_filter);
    if (params.sort_by) query.append('sort_by', params.sort_by);
    if (params.sort_order) query.append('sort_order', params.sort_order);
    if (params.page) query.append('page', params.page);
    if (params.page_size) query.append('page_size', params.page_size);

    const qs = query.toString();
    return this.request(`/vulnerabilities/inventory${qs ? '?' + qs : ''}`);
  },

  async getHostDetails(hostId) {
    return this.request(`/vulnerabilities/hosts/${hostId}`);
  },

  async updateVulnerabilityTreatment(vulnId, treatmentStatus, notes) {
    return this.request(`/vulnerabilities/${vulnId}/treatment`, {
      method: 'PATCH',
      body: JSON.stringify({
        treatment_status: treatmentStatus,
        treatment_notes: notes
      })
    });
  },

  async bulkUpdateVulnerabilityTreatment(vulnIds, treatmentStatus, notes) {
    return this.request('/vulnerabilities/bulk-treatment', {
      method: 'POST',
      body: JSON.stringify({
        vulnerability_ids: vulnIds,
        treatment_status: treatmentStatus,
        treatment_notes: notes
      })
    });
  },

  async getTreatmentHistory(vulnId) {
    return this.request(`/vulnerabilities/${vulnId}/treatment-history`);
  },

  // Action Plans Endpoints
  async listActionPlans(params = {}) {
    const query = new URLSearchParams();
    if (params.asset_group_id) query.append('asset_group_id', params.asset_group_id);
    if (params.status) query.append('status', params.status);
    if (params.priority) query.append('priority', params.priority);
    if (params.scope_type) query.append('scope_type', params.scope_type);
    if (params.tag) query.append('tag', params.tag);
    if (params.search) query.append('search', params.search);

    const qs = query.toString();
    return this.request(`/action-plans${qs ? '?' + qs : ''}`);
  },

  async getActionPlanStats(params = {}) {
    const query = new URLSearchParams();
    if (params.asset_group_id) query.append('asset_group_id', params.asset_group_id);
    const qs = query.toString();
    return this.request(`/action-plans/stats${qs ? '?' + qs : ''}`);
  },

  async getActionPlanTags() {
    return this.request('/action-plans/tags');
  },

  async createActionPlanTag(data) {
    return this.request('/action-plans/tags', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async getUnassignedVulns(params = {}) {
    const query = new URLSearchParams();
    if (params.asset_group_id) query.append('asset_group_id', params.asset_group_id);
    if (params.severity) query.append('severity', params.severity);
    if (params.search) query.append('search', params.search);
    if (params.limit) query.append('limit', params.limit);
    if (params.offset) query.append('offset', params.offset);
    const qs = query.toString();
    return this.request(`/action-plans/unassigned-vulns${qs ? '?' + qs : ''}`);
  },

  async previewActionPlanImpact(data) {
    return this.request('/action-plans/preview-impact', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async getActionPlanAssignees() {
    return this.request('/action-plans/assignees');
  },

  async getWizardOsList(assetGroupId = '') {
    const query = new URLSearchParams();
    if (assetGroupId) query.append('asset_group_id', assetGroupId);
    const qs = query.toString();
    return this.request(`/action-plans/wizard/os-list${qs ? '?' + qs : ''}`);
  },

  async getWizardHosts(assetGroupId = '', search = '', planId = '', os = '') {
    const query = new URLSearchParams();
    if (assetGroupId) query.append('asset_group_id', assetGroupId);
    if (search) query.append('search', search);
    if (planId) query.append('plan_id', planId);
    if (os) query.append('os', os);
    const qs = query.toString();
    return this.request(`/action-plans/wizard/hosts${qs ? '?' + qs : ''}`);
  },

  async getWizardVulnerabilities(assetGroupId = '', hostIps = '', search = '', planId = '') {
    const query = new URLSearchParams();
    if (assetGroupId) query.append('asset_group_id', assetGroupId);
    if (hostIps) query.append('host_ips', hostIps);
    if (search) query.append('search', search);
    if (planId) query.append('plan_id', planId);
    const qs = query.toString();
    return this.request(`/action-plans/wizard/vulnerabilities${qs ? '?' + qs : ''}`);
  },

  async getActionPlan(planId) {
    return this.request(`/action-plans/${planId}`);
  },

  async createActionPlan(data) {
    return this.request('/action-plans', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async updateActionPlan(planId, data) {
    return this.request(`/action-plans/${planId}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  async deleteActionPlan(planId) {
    return this.request(`/action-plans/${planId}`, {
      method: 'DELETE'
    });
  },

  async addActionTask(planId, data) {
    return this.request(`/action-plans/${planId}/tasks`, {
      method: 'POST',
      body: JSON.stringify(data)
    });
  },

  async updateActionTask(taskId, data) {
    return this.request(`/action-plans/tasks/${taskId}`, {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  },

  async deleteActionTask(taskId) {
    return this.request(`/action-plans/tasks/${taskId}`, {
      method: 'DELETE'
    });
  }
};

