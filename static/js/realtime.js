(() => {
    const el = id => document.getElementById(id);
    const fmtBytes = n => {
        n = Number(n) || 0;
        if (n < 1024) return n + ' B';
        if (n < 1048576) return (n / 1024).toFixed(2) + ' KB';
        if (n < 1073741824) return (n / 1048576).toFixed(2) + ' MB';
        return (n / 1073741824).toFixed(2) + ' GB';
    };
    const fmtTime = ts => {
        const d = new Date(ts * 1000);
        return d.toLocaleTimeString('zh-CN', { hour12: false });
    };

    const ctx = el('trafficChart').getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, 'rgba(56,189,248,0.32)');
    gradient.addColorStop(1, 'rgba(56,189,248,0.02)');
    const chart = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [{
            label: 'bytes/bucket',
            data: [],
            borderColor: '#38bdf8',
            backgroundColor: gradient,
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: '#38bdf8',
        }]},
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(2,6,23,0.95)',
                    borderColor: 'rgba(56,189,248,0.4)', borderWidth: 1,
                    padding: 10, titleColor: '#f8fafc', bodyColor: '#94a3b8',
                },
            },
            scales: {
                x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.04)' } },
                y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(148,163,184,0.06)' } },
            },
        },
    });

    function applyBuckets(buckets) {
        chart.data.labels = buckets.map(b => fmtTime(b.ts));
        chart.data.datasets[0].data = buckets.map(b => b.bytes);
        chart.update('none');
    }

    function animateKPI(elId, targetVal, suffix) {
        const element = document.getElementById(elId);
        if (!element) return;
        const parsed = parseFloat(String(targetVal).replace(/[^0-9.-]/g, '')) || 0;
        const duration = 600;
        const increments = 20;
        const step = parsed / increments;
        let current = 0;
        function tick() {
            current += step;
            if (current >= parsed) {
                element.textContent = suffix ? parsed + suffix : parsed;
                return;
            }
            element.textContent = suffix ? Math.round(current) + suffix : Math.round(current);
            requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }

    function applyMetrics(s) {
        if (!s) return;
        const m = s.metrics || {};
        animateKPI('kpiEvents', m.sent_events || 0, '');
        el('kpiBytes').textContent = fmtBytes(m.total_bytes || 0);
        animateKPI('kpiUsers', m.unique_users || 0, '');
        animateKPI('kpiIps', m.unique_src_ips || 0, '');
        animateKPI('kpiAlerts', m.alerts_triggered || 0, '');
        applyBuckets(s.traffic_buckets || []);
        const pill = el('statusPill');
        pill.classList.remove('running', 'stopped');
        pill.classList.add(s.running ? 'running' : 'stopped');
        el('statusText').textContent = s.running ? `运行中 · ${s.rate}/s` : '已停止';
        el('startBtn').disabled = !!s.running;
        el('stopBtn').disabled = !s.running;
    }

    let eventTimestamps = [];
    function updateEventRate() {
        var now = Date.now();
        eventTimestamps.push(now);
        var cutoff = now - 5000;
        eventTimestamps = eventTimestamps.filter(function(t) { return t > cutoff; });
        var rate = (eventTimestamps.length / 5).toFixed(1);
        el('kpiRate').textContent = rate + '/s';
    }

    let paused = false;
    let pausedEvents = [];

    const tbody = el('eventTable').querySelector('tbody');
    function appendEvent(ev) {
        if (paused) { pausedEvents.push(ev); return; }
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${fmtTime(ev.ts)}</td>
            <td>${ev.user}</td>
            <td>${ev.src_ip}</td>
            <td>${ev.dst_ip}:${ev.dst_port}</td>
            <td>${ev.protocol}</td>
            <td>${ev.app_category}</td>
            <td class="num">${ev.bytes}</td>
        `;
        tbody.prepend(tr);
        while (tbody.children.length > 30) tbody.removeChild(tbody.lastChild);
        updateEventRate();
    }

    const alertList = el('alertList');
    let alertCleared = false;
    function playAlertSound() {
        try {
            var audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            var osc = audioCtx.createOscillator();
            var gain = audioCtx.createGain();
            osc.connect(gain);
            gain.connect(audioCtx.destination);
            osc.type = 'sine';
            osc.frequency.setValueAtTime(880, audioCtx.currentTime);
            osc.frequency.setValueAtTime(660, audioCtx.currentTime + 0.12);
            gain.gain.setValueAtTime(0.3, audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
            osc.start(audioCtx.currentTime);
            osc.stop(audioCtx.currentTime + 0.25);
        } catch(e) {}
    }

    function filterAlerts() {
        var q = (el('alertSearch').value || '').toLowerCase().trim();
        var items = alertList.querySelectorAll('.alert-item');
        items.forEach(function(item) {
            var text = (item.textContent || '').toLowerCase();
            item.style.display = !q || text.indexOf(q) !== -1 ? '' : 'none';
        });
    }

    function appendAlert(a) {
        if (paused) { pausedEvents.push(a); return; }
        if (!alertCleared) { alertList.innerHTML = ''; alertCleared = true; }
        const div = document.createElement('div');
        div.className = `alert-item ${a.level}`;
        div.innerHTML = `
            <div class="alert-title" data-level="${a.level}">${a.title}</div>
            <div class="alert-meta">${fmtTime(a.ts)} · ${a.entity}</div>
            <div class="alert-detail">${a.detail}</div>
            <button class="btn alert-ack-btn" type="button" style="margin-top:8px;min-height:28px;padding:0 10px;font-size:11px;" data-id="${a.ts}-${Math.random().toString(36).slice(2,6)}">确认</button>
        `;
        div.querySelector('.alert-ack-btn').addEventListener('click', function() {
            div.style.opacity = '0.3';
            div.style.pointerEvents = 'none';
            this.textContent = '已确认';
        });
        alertList.prepend(div);
        while (alertList.children.length > 50) alertList.removeChild(alertList.lastChild);
        playAlertSound();
        updateEventRate();
        filterAlerts();
    }

    function renderML(report) {
        const box = el('mlBox');
        if (!report || !report.anomalies || !report.anomalies.length) {
            const msg = report?.message || '当前样本未发现异常用户';
            box.innerHTML = `<div class="ml-empty">${msg}<br><span style="opacity: 0.6;">模型: ${report?.model || '未运行'}</span></div>`;
            return;
        }
        const rows = report.anomalies.map((a, idx) => `
            <tr class="alert-${a.severity === 'critical' || a.severity === 'high' ? 'high' : 'medium'}">
                <td>${idx + 1}</td>
                <td><strong style="color: var(--text);">${a.user}</strong></td>
                <td class="num">${a.anomaly_score.toFixed(1)}</td>
                <td><span class="severity-badge ${a.severity}">${a.severity}</span></td>
                <td style="color: var(--muted); font-size: 11px;">${(a.evidence || []).join(' · ')}</td>
            </tr>
        `).join('');
        box.innerHTML = `
            <div class="ml-summary">
                共 <strong>${report.summary.total_users}</strong> 用户 ·
                <strong>${report.summary.anomaly_users}</strong> 个异常 ·
                contamination=<strong>${report.config.contamination}</strong>
            </div>
            <div class="table-wrap" style="max-height: 300px;">
                <table>
                    <thead><tr><th>#</th><th>用户</th><th class="num">分数</th><th>等级</th><th>关键证据</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    function updateSSEIndicator(connected) {
        var dot = document.getElementById('sse-indicator');
        var txt = document.getElementById('sse-text');
        if (!dot || !txt) return;
        dot.style.background = connected ? 'var(--green)' : 'var(--red)';
        dot.style.boxShadow = connected ? '0 0 10px rgba(34,197,94,0.8)' : '0 0 10px rgba(239,68,68,0.8)';
        txt.textContent = connected ? 'SSE 已连接' : 'SSE 断开';
    }

    let evtSource = null;
    function connectSSE() {
        if (evtSource) evtSource.close();
        evtSource = new EventSource('/api/realtime/stream');
        evtSource.addEventListener('open', function() {
            updateSSEIndicator(true);
        });
        evtSource.addEventListener('snapshot', e => {
            const s = JSON.parse(e.data);
            applyMetrics(s);
            (s.recent_events || []).slice(-20).forEach(appendEvent);
        });
        evtSource.addEventListener('event', e => appendEvent(JSON.parse(e.data)));
        evtSource.addEventListener('metrics', e => applyMetrics(JSON.parse(e.data)));
        evtSource.addEventListener('alert', e => appendAlert(JSON.parse(e.data)));
        evtSource.addEventListener('finished', () => {
            const pill = el('statusPill');
            pill.classList.remove('running');
            pill.classList.add('stopped');
            el('statusText').textContent = '已结束';
            el('startBtn').disabled = false;
            el('stopBtn').disabled = true;
        });
        evtSource.onerror = function() {
            updateSSEIndicator(false);
        };
    }

    el('pauseBtn').onclick = function() {
        paused = !paused;
        this.textContent = paused ? '▶ 恢复' : '⏸ 暂停';
        this.classList.toggle('primary');
        if (!paused && pausedEvents.length) {
            var events = pausedEvents.slice();
            pausedEvents = [];
            events.forEach(function(ev) {
                if (ev.title !== undefined) {
                    if (!alertCleared) { alertList.innerHTML = ''; alertCleared = true; }
                    var div = document.createElement('div');
                    div.className = 'alert-item ' + ev.level;
                    div.innerHTML = '<div class="alert-title" data-level="' + ev.level + '">' + ev.title + '</div><div class="alert-meta">' + fmtTime(ev.ts) + ' · ' + ev.entity + '</div><div class="alert-detail">' + ev.detail + '</div>';
                    alertList.prepend(div);
                    while (alertList.children.length > 50) alertList.removeChild(alertList.lastChild);
                } else {
                    var tr = document.createElement('tr');
                    tr.innerHTML = '<td>' + fmtTime(ev.ts) + '</td><td>' + ev.user + '</td><td>' + ev.src_ip + '</td><td>' + ev.dst_ip + ':' + ev.dst_port + '</td><td>' + ev.protocol + '</td><td>' + ev.app_category + '</td><td class="num">' + ev.bytes + '</td>';
                    tbody.prepend(tr);
                    while (tbody.children.length > 30) tbody.removeChild(tbody.lastChild);
                }
            });
        }
    };

    el('startBtn').onclick = async () => {
        const rate = parseFloat(el('rateInput').value) || 5;
        await fetch('/api/realtime/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rate, loop: true }),
        });
    };
    el('stopBtn').onclick = async () => {
        await fetch('/api/realtime/stop', { method: 'POST' });
    };
    el('applyRateBtn').onclick = async () => {
        const rate = parseFloat(el('rateInput').value) || 5;
        const btn = el('applyRateBtn');
        const original = btn.textContent;
        btn.disabled = true;
        btn.textContent = '已应用';
        try {
            await fetch('/api/realtime/rate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rate }),
            });
        } finally {
            setTimeout(() => { btn.textContent = original; btn.disabled = false; }, 800);
        }
    };

    el('alertSearch').addEventListener('input', filterAlerts);

    fetch('/api/realtime/status').then(r => r.json()).then(applyMetrics);
    fetch('/api/ml_anomaly').then(r => r.json()).then(renderML);
    connectSSE();
})();