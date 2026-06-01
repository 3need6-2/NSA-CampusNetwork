const charts = {};
let dashboardData = {};
let userProfilesData = {};

const palette = {
    cyan: '#38bdf8',
    green: '#22c55e',
    red: '#ef4444',
    amber: '#f59e0b',
    violet: '#8b5cf6',
    muted: '#64748b',
    text: '#f8fafc'
};

Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.14)';
Chart.defaults.font.family = 'Inter, "PingFang SC", "Microsoft YaHei", Arial, sans-serif';

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function formatBytes(bytes) {
    const value = Number(bytes || 0);
    if (value < 1024) return `${value} B`;
    if (value < 1024 ** 2) return `${(value / 1024).toFixed(2)} KB`;
    if (value < 1024 ** 3) return `${(value / (1024 ** 2)).toFixed(2)} MB`;
    return `${(value / (1024 ** 3)).toFixed(2)} GB`;
}

function destroyChart(id) {
    if (charts[id]) {
        charts[id].destroy();
        delete charts[id];
    }
}

async function loadDashboardData() {
    const status = document.getElementById('data-status');
    try {
        const response = await fetch('/api/dashboard_data');
        dashboardData = await response.json();
        if (!dashboardData.total_traffic) throw new Error('未读取到流量数据');
        status.textContent = '数据已同步';
        renderDashboard(dashboardData);
    } catch (error) {
        status.textContent = '数据加载失败';
        status.style.borderColor = 'rgba(239, 68, 68, 0.55)';
        document.querySelectorAll('.loading').forEach(el => {
            el.textContent = '请通过 Flask 启动项目后访问 /dashboard。';
        });
    }
}

function renderDashboard(data) {
    const traffic = data.total_traffic || {};
    const map = data.attack_map || {};
    const security = data.ai_security || {};
    const summary = security.summary || {};

    setText('attack-sources', `${map.sources || 0} IPs`);
    setText('top-target', map.top_target || '暂无');
    setText('quarantine-advice', map.blocked ?? 0);

    setText('total-bytes', formatBytes(traffic.total_bytes));
    setText('total-packets', traffic.total_packets || 0);
    setText('unique-users', traffic.unique_users || 0);
    setText('unique-ips', traffic.unique_ips || 0);

    const riskLevel = summary.risk_level || 'low';
    const riskBadge = document.getElementById('risk-level');
    riskBadge.textContent = riskLevel;
    riskBadge.className = `risk-badge ${riskLevel}`;
    setText('risk-score', summary.risk_score ?? 0);
    setText('alert-count', summary.total_alerts ?? 0);
    setText('deepseek-state', summary.deepseek_configured ? '已配置' : '未配置');

    renderBlockList(security.blocked_entities || []);
    renderActiveHours(data.active_hours || []);
    renderMLAnomaly(data.ml_anomaly || {});
    renderCharts(data);
}

function renderMLAnomaly(report) {
    const summary = report.summary || {};
    const config = report.config || {};
    setText('ml-model', report.model || '未运行');
    setText('ml-total', summary.total_users ?? '--');
    setText('ml-anomaly-count', summary.anomaly_users ?? '--');
    setText('ml-contamination', config.contamination ?? '--');
    setText('ml-max-score', summary.max_score ?? '--');

    const tbody = document.getElementById('ml-anomaly-tbody');
    const anomalies = report.anomalies || [];
    if (!anomalies.length) {
        const msg = report.status === 'skipped'
            ? (report.message || '未运行 ML 检测')
            : '当前样本未发现异常用户';
        tbody.innerHTML = `<tr><td colspan="5" class="table-empty">${msg}</td></tr>`;
        return;
    }
    tbody.innerHTML = anomalies.map((a, idx) => `
        <tr>
            <td>${idx + 1}</td>
            <td><strong>${a.user}</strong></td>
            <td>${(a.anomaly_score || 0).toFixed(1)}</td>
            <td><span class="risk-badge ${a.severity}">${a.severity}</span></td>
            <td>${(a.evidence || []).join(' · ')}</td>
        </tr>
    `).join('');
}

function renderBlockList(items) {
    const list = document.getElementById('block-list');
    if (!items.length) {
        list.innerHTML = '<div class="mini-item"><span>当前样本未触发隔离建议</span><strong>Monitor</strong></div>';
        return;
    }
    list.innerHTML = items.slice(0, 5).map(item => `
        <div class="mini-item">
            <span>${item.target_type}: ${item.target}</span>
            <strong>${item.action} / ${item.ttl_minutes}m</strong>
        </div>
    `).join('');
}

function renderActiveHours(items) {
    const body = document.getElementById('active-hours-table');
    if (!items.length) {
        body.innerHTML = '<tr><td colspan="4" class="table-empty">暂无小时统计</td></tr>';
        return;
    }
    body.innerHTML = items.map(item => `
        <tr>
            <td>${item.hour}</td>
            <td>${item.active_users}</td>
            <td>${item.packet_count}</td>
            <td>${formatBytes(item.total_bytes)}</td>
        </tr>
    `).join('');
}

function renderCharts(data) {
    const activeHours = data.active_hours || [];
    const appCategory = data.app_category || [];
    const userRanking = data.user_ranking || [];

    destroyChart('traffic');
    charts.traffic = new Chart(document.getElementById('traffic-trend-chart'), {
        type: 'line',
        data: {
            labels: activeHours.map(item => item.hour),
            datasets: [{
                label: '流量 MB',
                data: activeHours.map(item => Number(item.total_bytes || 0) / (1024 ** 2)),
                borderColor: palette.cyan,
                backgroundColor: 'rgba(56, 189, 248, 0.14)',
                fill: true,
                tension: 0.35,
                pointRadius: 3
            }]
        },
        options: chartOptions('MB')
    });

    destroyChart('app');
    charts.app = new Chart(document.getElementById('app-category-chart'), {
        type: 'doughnut',
        data: {
            labels: appCategory.map(item => item.category),
            datasets: [{
                data: appCategory.map(item => item.bytes),
                backgroundColor: [palette.cyan, palette.green, palette.amber, palette.violet, palette.red, '#14b8a6', '#e879f9'],
                borderColor: '#020617',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right' },
                tooltip: { callbacks: { label: ctx => `${ctx.label}: ${formatBytes(ctx.raw)}` } }
            }
        }
    });

    destroyChart('ranking');
    charts.ranking = new Chart(document.getElementById('user-ranking-chart'), {
        type: 'bar',
        data: {
            labels: userRanking.map(item => item.user),
            datasets: [{
                label: '流量 MB',
                data: userRanking.map(item => Number(item.bytes || 0) / (1024 ** 2)),
                backgroundColor: 'rgba(34, 197, 94, 0.72)',
                borderColor: palette.green,
                borderWidth: 1
            }]
        },
        options: {
            ...chartOptions('MB'),
            indexAxis: 'y'
        }
    });
}

function chartOptions(unit) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
            legend: { labels: { boxWidth: 10 } },
            tooltip: {
                callbacks: {
                    label: ctx => `${ctx.dataset.label}: ${Number(ctx.raw).toFixed(2)} ${unit}`
                }
            }
        },
        scales: {
            x: { grid: { color: 'rgba(148, 163, 184, 0.10)' } },
            y: { beginAtZero: true, grid: { color: 'rgba(148, 163, 184, 0.10)' } }
        }
    };
}

async function loadUserProfiles() {
    try {
        const response = await fetch('/api/user_profiles');
        userProfilesData = await response.json();
        var filterInput = document.getElementById('user-search-input');
        renderUserTags(filterInput ? filterInput.value : '');
    } catch (error) {
        document.getElementById('user-tags-container').innerHTML = '<div class="loading">用户画像加载失败。</div>';
    }
}

function renderUserTags(filter) {
    const container = document.getElementById('user-tags-container');
    const entries = Object.entries(userProfilesData || {});
    if (!entries.length) {
        container.innerHTML = '<div class="loading">暂无用户画像。</div>';
        return;
    }

    const q = (filter || '').toLowerCase().trim();
    const filtered = q ? entries.filter(([userId]) => userId.toLowerCase().includes(q)) : entries.slice(0, 12);

    if (!filtered.length) {
        container.innerHTML = '<div class="loading">未找到匹配的用户。</div>';
        return;
    }

    container.innerHTML = filtered.map(([userId, profile]) => `
        <button class="user-card" type="button" data-user="${userId}">
            <strong>${userId}</strong>
            <div class="tag-row">
                ${(profile.tags || []).slice(0, 5).map(tag => `<span class="pill">${tag}</span>`).join('')}
            </div>
        </button>
    `).join('');

    container.querySelectorAll('.user-card').forEach(card => {
        card.addEventListener('click', () => showUserDetail(card.dataset.user));
    });
}

if (document.getElementById('user-search-input')) {
    document.getElementById('user-search-input').addEventListener('input', function() {
        renderUserTags(this.value);
    });
}

function showUserDetail(userId) {
    const profile = userProfilesData[userId];
    if (!profile) return;

    document.getElementById('user-detail-panel').style.display = 'grid';
    document.getElementById('detail-user-name').textContent = `用户详情 - ${userId}`;

    renderCategoryChart(profile.category_pct || {});
    renderProtocolChart(profile.protocol_ratio || {});
    renderHoursChart(profile.active_hours || {});
    document.getElementById('user-detail-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderCategoryChart(categoryData) {
    destroyChart('userCategory');
    charts.userCategory = new Chart(document.getElementById('user-category-chart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(categoryData),
            datasets: [{
                data: Object.values(categoryData),
                backgroundColor: [palette.cyan, palette.green, palette.amber, palette.violet, palette.red, '#14b8a6']
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } } }
    });
}

function renderProtocolChart(protocolData) {
    destroyChart('protocol');
    charts.protocol = new Chart(document.getElementById('user-protocol-chart'), {
        type: 'pie',
        data: {
            labels: Object.keys(protocolData),
            datasets: [{
                data: Object.values(protocolData),
                backgroundColor: [palette.cyan, palette.violet, palette.green, palette.amber]
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } } }
    });
}

function renderHoursChart(hoursData) {
    const hours = Array.from({ length: 24 }, (_, i) => i);
    destroyChart('userHours');
    charts.userHours = new Chart(document.getElementById('user-hours-chart'), {
        type: 'bar',
        data: {
            labels: hours.map(h => `${String(h).padStart(2, '0')}:00`),
            datasets: [{
                label: '流量 MB',
                data: hours.map(h => Number(hoursData[h]?.bytes || 0) / (1024 ** 2)),
                backgroundColor: 'rgba(56, 189, 248, 0.65)'
            }]
        },
        options: chartOptions('MB')
    });
}

async function runDeepSeekReview() {
    const button = document.getElementById('deepseek-review-btn');
    const result = document.getElementById('deepseek-review-result');
    button.disabled = true;
    button.textContent = '审查中...';
    result.textContent = '正在调用 DeepSeek 进行防守性复核。';

    try {
        const response = await fetch('/api/ai_security/deepseek', { method: 'POST' });
        const data = await response.json();
        const review = data.deepseek_review || {};
        if (review.status === 'ok') {
            const aiResult = review.result || {};
            result.textContent = [
                `风险等级：${aiResult.risk_level || 'unknown'}`,
                `结论：${aiResult.summary || 'DeepSeek 已完成审查。'}`,
                `建议：${(aiResult.recommended_actions || []).slice(0, 3).join('；')}`
            ].join('\n');
        } else {
            result.textContent = review.message || 'DeepSeek 未完成审查，请检查 API Key 或网络。';
        }
        await loadDashboardData();
    } catch (error) {
        result.textContent = `DeepSeek 审查请求失败：${error}`;
    } finally {
        button.disabled = false;
        button.textContent = '运行 DeepSeek 审查';
    }
}

async function refreshMLAnomaly() {
    const btn = document.getElementById('ml-refresh-btn');
    const note = document.getElementById('ml-refresh-note');
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = '正在重新计算...';
    note.textContent = '';
    try {
        const resp = await fetch('/api/ml_anomaly/refresh', { method: 'POST' });
        const report = await resp.json();
        renderMLAnomaly(report);
        note.textContent = `已重新计算：异常用户 ${report.summary?.anomaly_users ?? 0} 个`;
    } catch (e) {
        note.textContent = `刷新失败：${e}`;
    } finally {
        btn.disabled = false;
        btn.textContent = original;
    }
}

var autoRefreshInterval = null;

function toggleAutoRefresh() {
    var btn = document.getElementById('auto-refresh-btn');
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        btn.textContent = '自动刷新: 关';
        btn.style.borderColor = 'var(--border)';
    } else {
        autoRefreshInterval = setInterval(function() {
            loadDashboardData();
        }, 30000);
        btn.textContent = '自动刷新: 开 (30s)';
        btn.style.borderColor = 'rgba(34,197,94,0.6)';
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadDashboardData();
    loadUserProfiles();
    var refreshBtn = document.getElementById('auto-refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', toggleAutoRefresh);
});

document.addEventListener('keydown', function(e) {
    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
        var modal = document.getElementById('shortcuts-modal');
        modal.style.display = modal.style.display === 'flex' ? 'none' : 'flex';
    }
    if (e.key === 'Escape') {
        var modal = document.getElementById('shortcuts-modal');
        if (modal.style.display === 'flex') modal.style.display = 'none';
        if (document.fullscreenElement) document.exitFullscreen();
    }
    if ((e.key === 'f' || e.key === 'F') && !e.ctrlKey && !e.metaKey) {
        toggleFullscreen();
    }
    if ((e.key === 'r' || e.key === 'R') && !e.ctrlKey && !e.metaKey) {
        loadDashboardData();
    }
});

function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
    } else {
        document.exitFullscreen();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.download-chart-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var chartId = this.dataset.chart;
            var chart = charts[chartId];
            if (chart) {
                var link = document.createElement('a');
                link.download = chartId + '-chart.png';
                link.href = chart.toBase64Image();
                link.click();
            }
        });
    });

    document.getElementById('deepseek-review-btn')?.addEventListener('click', runDeepSeekReview);
    document.getElementById('ml-refresh-btn')?.addEventListener('click', refreshMLAnomaly);
    document.getElementById('auto-refresh-btn')?.addEventListener('click', toggleAutoRefresh);
    document.getElementById('fullscreen-btn')?.addEventListener('click', toggleFullscreen);
    document.getElementById('close-shortcuts-btn')?.addEventListener('click', function() {
        document.getElementById('shortcuts-modal').style.display = 'none';
    });

    document.querySelectorAll('.toggle-btn[data-target]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var target = document.getElementById(this.dataset.target);
            if (!target) return;
            var isCollapsed = target.style.maxHeight === '0px' || target.dataset.collapsed === 'true';
            if (isCollapsed) {
                target.style.maxHeight = target.scrollHeight + 'px';
                target.dataset.collapsed = 'false';
                this.textContent = '折叠';
            } else {
                target.style.maxHeight = '0px';
                target.dataset.collapsed = 'true';
                this.textContent = '展开';
            }
        });
    });

    document.getElementById('comp-btn')?.addEventListener('click', async function() {
        const a = document.getElementById('comp-user-a').value.trim();
        const b = document.getElementById('comp-user-b').value.trim();
        if (!a || !b) return;
        const box = document.getElementById('comp-results');
        box.innerHTML = '<div class="loading" style="grid-column:1/-1;">正在加载对比数据...</div>';
        try {
            const resp = await fetch(`/api/user_comparison?user_a=${encodeURIComponent(a)}&user_b=${encodeURIComponent(b)}`);
            const data = await resp.json();
            if (data.error) { box.innerHTML = `<div class="loading" style="grid-column:1/-1;">${data.error}</div>`; return; }
            const ua = data.user_a || {}, ub = data.user_b || {}, diff = data.diff || {};
            box.innerHTML = `
                <div class="panel" style="background:rgba(34,197,94,0.06);border-color:rgba(34,197,94,0.25);">
                    <h3 style="color:var(--green);">${ua.user || a}</h3>
                    <div class="mini-list">
                        <div class="mini-item"><span>总流量</span><strong>${formatBytes(ua.total_bytes)}</strong></div>
                        <div class="mini-item"><span>总包数</span><strong>${ua.total_packets}</strong></div>
                        <div class="mini-item"><span>活跃小时</span><strong>${ua.active_hours}</strong></div>
                        <div class="mini-item"><span>协议</span><strong>${Object.keys(ua.protocols || {}).join(', ') || '-'}</strong></div>
                        <div class="mini-item"><span>类别</span><strong>${Object.keys(ua.categories || {}).join(', ') || '-'}</strong></div>
                    </div>
                </div>
                <div class="panel" style="background:rgba(139,92,246,0.06);border-color:rgba(139,92,246,0.25);">
                    <h3 style="color:var(--violet);">${ub.user || b}</h3>
                    <div class="mini-list">
                        <div class="mini-item"><span>总流量</span><strong>${formatBytes(ub.total_bytes)}</strong></div>
                        <div class="mini-item"><span>总包数</span><strong>${ub.total_packets}</strong></div>
                        <div class="mini-item"><span>活跃小时</span><strong>${ub.active_hours}</strong></div>
                        <div class="mini-item"><span>协议</span><strong>${Object.keys(ub.protocols || {}).join(', ') || '-'}</strong></div>
                        <div class="mini-item"><span>类别</span><strong>${Object.keys(ub.categories || {}).join(', ') || '-'}</strong></div>
                    </div>
                </div>
                <div class="panel" style="grid-column:1/-1;border-color:rgba(245,158,11,0.3);">
                    <h3 style="color:var(--amber);">差异</h3>
                    <div class="mini-list" style="grid-template-columns:1fr 1fr;">
                        <div class="mini-item"><span>流量差 (A-B)</span><strong>${formatBytes(diff.bytes_diff)}</strong></div>
                        <div class="mini-item"><span>包数差 (A-B)</span><strong>${diff.packets_diff}</strong></div>
                    </div>
                </div>
            `;
        } catch(e) {
            box.innerHTML = `<div class="loading" style="grid-column:1/-1;">对比失败: ${e}</div>`;
        }
    });
});