/**
 * GvulStand Chart Utilities (Chart.js Integration with Modern Corporate Design)
 * Paleta Funcional CVSS 3.1 & Cores da Marca (Verde Petróleo e Azul Profundo)
 */
const AppCharts = {
  severityChart: null,
  assetGroupChart: null,
  comparativeChart: null,
  exploitableChart: null,
  scanHealthChart: null,
  trendChart: null,

  getThemeColors() {
    const isDark = document.documentElement.classList.contains('dark');
    return {
      isDark,
      fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif",
      textColor: isDark ? '#94A3B8' : '#64748B',
      gridColor: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
      borderColor: isDark ? '#131B2E' : '#FFFFFF',
      tooltipBg: isDark ? '#0F172A' : '#FFFFFF',
      tooltipTitle: isDark ? '#F8FAFC' : '#0F172A',
      tooltipBody: isDark ? '#94A3B8' : '#475569',
      tooltipBorder: isDark ? '#1E293B' : '#E2E8F0',
      emptyBg: isDark ? '#1E293B' : '#E2E8F0'
    };
  },

  initSeverityChart(ctx, data) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.severityChart) {
      try { this.severityChart.destroy(); } catch(e) {}
    }

    const colors = this.getThemeColors();
    data = data || {};
    const counts = [
      data.Critical || 0,
      data.High || 0,
      data.Medium || 0,
      data.Low || 0
    ];

    const total = counts.reduce((a, b) => a + b, 0);

    try {
      this.severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Crítica', 'Alta', 'Média', 'Baixa'],
          datasets: [{
            data: total === 0 ? [0, 0, 0, 1] : counts,
            backgroundColor: total === 0 ? [colors.emptyBg] : [
              '#DC2626', // Critical (CVSS Red)
              '#EA580C', // High (CVSS Orange)
              '#D97706', // Medium (CVSS Amber)
              '#0284C7'  // Low (CVSS Blue)
            ],
            borderColor: colors.borderColor,
            borderWidth: 3,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '72%',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: colors.textColor,
                font: { size: 12, family: colors.fontFamily, weight: '500' },
                padding: 16,
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 12,
              cornerRadius: 8,
              boxPadding: 4,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating severity chart:', err);
    }
  },

  initAssetGroupChart(ctx, groupsData) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.assetGroupChart) {
      try { this.assetGroupChart.destroy(); } catch(e) {}
    }

    const colors = this.getThemeColors();
    groupsData = groupsData || [];
    const labels = groupsData.map(g => g.name);
    const criticals = groupsData.map(g => g.critical);
    const highs = groupsData.map(g => g.high);
    const mediums = groupsData.map(g => g.medium);
    const lows = groupsData.map(g => g.low);

    try {
      this.assetGroupChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels.length ? labels : ['Nenhum Grupo'],
          datasets: [
            {
              label: 'Crítica',
              data: criticals.length ? criticals : [0],
              backgroundColor: '#DC2626',
              borderRadius: 6
            },
            {
              label: 'Alta',
              data: highs.length ? highs : [0],
              backgroundColor: '#EA580C',
              borderRadius: 6
            },
            {
              label: 'Média',
              data: mediums.length ? mediums : [0],
              backgroundColor: '#D97706',
              borderRadius: 6
            },
            {
              label: 'Baixa',
              data: lows.length ? lows : [0],
              backgroundColor: '#0284C7',
              borderRadius: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              stacked: true,
              grid: { color: colors.gridColor },
              ticks: { color: colors.textColor, font: { size: 11, family: colors.fontFamily } }
            },
            y: {
              stacked: true,
              grid: { color: colors.gridColor },
              ticks: { color: colors.textColor, font: { size: 11, family: colors.fontFamily } }
            }
          },
          plugins: {
            legend: {
              position: 'top',
              labels: {
                color: colors.textColor,
                font: { size: 12, family: colors.fontFamily, weight: '500' },
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 12,
              cornerRadius: 8,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating asset group chart:', err);
    }
  },

  initComparativeChart(ctx, beforeData, afterData) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.comparativeChart) {
      try { this.comparativeChart.destroy(); } catch(e) {}
    }

    const colors = this.getThemeColors();
    beforeData = beforeData || {};
    afterData = afterData || {};

    try {
      this.comparativeChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ['Crítica', 'Alta', 'Média', 'Baixa', 'Total'],
          datasets: [
            {
              label: 'Antes (Baseline)',
              data: [
                beforeData.Critical || 0,
                beforeData.High || 0,
                beforeData.Medium || 0,
                beforeData.Low || 0,
                (beforeData.Critical || 0) + (beforeData.High || 0) + (beforeData.Medium || 0) + (beforeData.Low || 0)
              ],
              backgroundColor: 'rgba(220, 38, 38, 0.85)', // Red
              borderColor: '#DC2626',
              borderWidth: 1,
              borderRadius: 6
            },
            {
              label: 'Depois (Pós-Tratativa)',
              data: [
                afterData.Critical || 0,
                afterData.High || 0,
                afterData.Medium || 0,
                afterData.Low || 0,
                (afterData.Critical || 0) + (afterData.High || 0) + (afterData.Medium || 0) + (afterData.Low || 0)
              ],
              backgroundColor: 'rgba(15, 118, 110, 0.85)', // Verde Petróleo (#0F766E)
              borderColor: '#0F766E',
              borderWidth: 1,
              borderRadius: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              grid: { color: colors.gridColor },
              ticks: { color: colors.textColor, font: { size: 12, family: colors.fontFamily } }
            },
            y: {
              grid: { color: colors.gridColor },
              ticks: { color: colors.textColor, font: { size: 12, family: colors.fontFamily } }
            }
          },
          plugins: {
            legend: {
              position: 'top',
              labels: { color: colors.textColor, font: { size: 12, family: colors.fontFamily, weight: '500' } }
            },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 12,
              cornerRadius: 8,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating comparative chart:', err);
    }
  },

  initExploitableTypesChart(ctx, data) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.exploitableChart) {
      try { this.exploitableChart.destroy(); } catch(e) {}
    }

    const colors = this.getThemeColors();
    data = data || {};
    const values = [
      data.malware || 0,
      data.remote_low || 0,
      data.local_low || 0,
      data.framework_metasploit || 0,
      data.remote_high || 0
    ];

    try {
      this.exploitableChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: [
            'Explorado por Malware',
            'Remoto (Baixa Compl.)',
            'Local (Baixa Compl.)',
            'Framework (Metasploit)',
            'Remoto (Alta Compl.)'
          ],
          datasets: [{
            data: values,
            backgroundColor: [
              '#DC2626', // Explorado por Malware (Ameaça Crítica)
              '#EA580C', // Remoto Baixa Compl. (Alta Exposição)
              '#0F766E', // Local Baixa Compl. (Verde Petróleo Institucional)
              '#7C3AED', // Framework Metasploit (Púrpura Exploit Ativo)
              '#0284C7'  // Remoto Alta Compl. (Azul Oceano)
            ],
            borderRadius: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 12,
              cornerRadius: 8,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' },
              callbacks: {
                label: (ctx) => ` Vulnerabilidades: ${ctx.raw.toLocaleString()}`
              }
            }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: colors.textColor, font: { size: 10, family: colors.fontFamily } }
            },
            y: {
              grid: { color: colors.gridColor },
              ticks: { color: colors.textColor, font: { size: 10, family: colors.fontFamily } }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating exploitable types chart:', err);
    }
  },

  initScanHealthChart(ctx, data) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.scanHealthChart) {
      try { this.scanHealthChart.destroy(); } catch(e) {}
    }

    const colors = this.getThemeColors();
    data = data || {};
    const rawValues = [
      data.auth_success || 0,
      data.insufficient_access || 0,
      data.intermittent || 0,
      data.auth_failure || 0,
      data.no_credentials || 0
    ];

    const total = rawValues.reduce((a, b) => a + b, 0);

    try {
      this.scanHealthChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: [
            'Autenticação com Sucesso',
            'Sucesso c/ Acesso Insuficiente',
            'Sucesso c/ Falha Intermitente',
            'Falha de Autenticação (Credenciais)',
            'Sem Credenciais Fornecidas'
          ],
          datasets: [{
            data: total === 0 ? [0, 0, 0, 0, 1] : rawValues,
            backgroundColor: [
              '#10B981', // Sucesso (Verde Esmeralda)
              '#0284C7', // Sucesso c/ Acesso Insuficiente (Azul Oceano)
              '#D97706', // Intermitente (Âmbar Vibrante)
              '#EA580C', // Falha (Laranja Coral)
              total === 0 ? colors.emptyBg : '#DC2626' // Sem Credenciais (Vermelho CVSS)
            ],
            borderColor: colors.borderColor,
            borderWidth: 3,
            hoverOffset: 6
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '68%',
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: colors.textColor,
                font: { size: 10, family: colors.fontFamily, weight: '500' },
                padding: 12,
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 12,
              cornerRadius: 8,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' },
              callbacks: {
                label: (ctx) => ` ${ctx.label}: ${ctx.raw} hosts`
              }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating scan health chart:', err);
    }
  },

  initTrendChart(ctx, trendData) {
    if (!ctx || typeof Chart === 'undefined') return;
    if (this.trendChart) {
      try { this.trendChart.destroy(); } catch(e) {}
      this.trendChart = null;
    }

    const emptyEl = document.getElementById('chart-trend-empty');
    const legendEl = document.getElementById('chart-trend-legend');

    trendData = trendData || {};
    const labels = Array.isArray(trendData.labels) ? trendData.labels : [];
    const discovered = Array.isArray(trendData.discovered) ? trendData.discovered : [];
    const remediated = Array.isArray(trendData.remediated) ? trendData.remediated : [];
    const hasSufficientData = Boolean(trendData.has_sufficient_data && labels.length >= 2);

    if (!hasSufficientData) {
      if (emptyEl) emptyEl.classList.remove('hidden');
      ctx.style.display = 'none';
      if (legendEl) {
        legendEl.textContent = 'Histórico temporal consolidado dos últimos meses (mínimo de 2 períodos de varredura requeridos).';
      }
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
      return;
    }

    if (emptyEl) emptyEl.classList.add('hidden');
    ctx.style.display = 'block';
    if (legendEl) {
      legendEl.textContent = 'Linha vermelha representa volume descoberto; linha verde petróleo confirma resolução efetiva em retestes.';
    }

    const colors = this.getThemeColors();

    try {
      this.trendChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'Descobertas (Risco Aberto)',
              data: discovered,
              borderColor: '#DC2626',
              backgroundColor: colors.isDark ? 'rgba(220, 38, 38, 0.15)' : 'rgba(220, 38, 38, 0.08)',
              borderWidth: 2.5,
              tension: 0.35,
              fill: true,
              pointRadius: 4,
              pointHoverRadius: 6,
              pointBackgroundColor: '#DC2626'
            },
            {
              label: 'Remediadas (Tratadas)',
              data: remediated,
              borderColor: '#0F766E',
              backgroundColor: colors.isDark ? 'rgba(20, 184, 166, 0.18)' : 'rgba(15, 118, 110, 0.10)',
              borderWidth: 2.5,
              tension: 0.35,
              fill: true,
              pointRadius: 4,
              pointHoverRadius: 6,
              pointBackgroundColor: '#0F766E'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false
          },
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: colors.textColor,
                font: { size: 11, family: colors.fontFamily, weight: '500' },
                padding: 14,
                usePointStyle: true,
                pointStyle: 'circle'
              }
            },
            tooltip: {
              backgroundColor: colors.tooltipBg,
              titleColor: colors.tooltipTitle,
              bodyColor: colors.tooltipBody,
              borderColor: colors.tooltipBorder,
              borderWidth: 1,
              padding: 10,
              cornerRadius: 8,
              bodyFont: { family: colors.fontFamily },
              titleFont: { family: colors.fontFamily, weight: 'bold' },
              callbacks: {
                label: function(context) {
                  const label = context.dataset.label || '';
                  const value = context.parsed.y !== null ? context.parsed.y.toLocaleString() : 0;
                  return ` ${label}: ${value}`;
                }
              }
            }
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { color: colors.textColor, font: { size: 11, family: colors.fontFamily } }
            },
            y: {
              beginAtZero: true,
              grid: { color: colors.gridColor },
              ticks: { 
                color: colors.textColor, 
                font: { size: 11, family: colors.fontFamily },
                callback: function(val) {
                  return Number(val).toLocaleString();
                }
              }
            }
          }
        }
      });
    } catch (err) {
      console.error('Error creating trend chart:', err);
    }
  },
};
