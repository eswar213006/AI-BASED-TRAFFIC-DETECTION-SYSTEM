/* ==========================================================================
   AI NETWORK INTRUSION DETECTION SYSTEM - FRONTEND JAVASCRIPT
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    
    // State Variables
    let isMonitoring = false;
    let monitoringIntervalId = null;
    let charts = {};

    // =========================================================================
    // INITIALIZATION & EVENT LISTENERS
    // =========================================================================
    
    initNavigation();
    initCharts();
    initModals();
    initAccordion();
    loadDashboardData();
    loadModelPerformance();
    loadTrafficAnalysis();

    // Auto refresh every 4 seconds
    setInterval(() => {
        loadDashboardData();
        updateClock();
    }, 4000);

    updateClock();

    // =========================================================================
    // NAVIGATION
    // =========================================================================
    
    function initNavigation() {
        const navLinks = document.querySelectorAll('.nav-link, .nav-link-trigger');
        
        navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = link.getAttribute('data-target');
                if (!targetId) return;

                // Update active link state
                document.querySelectorAll('.nav-link').forEach(nl => nl.classList.remove('active'));
                const activeNav = document.querySelector(`.nav-link[data-target="${targetId}"]`);
                if (activeNav) activeNav.classList.add('active');

                // Switch visible view
                document.querySelectorAll('.page-view').forEach(view => view.classList.remove('active'));
                const targetView = document.getElementById(targetId);
                if (targetView) targetView.classList.add('active');

                // Reload page specific data if needed
                if (targetId === 'view-performance') loadModelPerformance();
                if (targetId === 'view-analysis') loadTrafficAnalysis();
                if (targetId === 'view-alerts') loadAlertsTable();
            });
        });
    }

    function updateClock() {
        const timeEl = document.getElementById('live-time-str');
        if (timeEl) {
            const now = new Date();
            timeEl.textContent = now.toLocaleTimeString();
        }
    }

    // =========================================================================
    // API CALLS & DATA LOADING
    // =========================================================================
    
    async function loadDashboardData() {
        try {
            // Fetch stats
            const resStats = await fetch('/api/stats');
            const dataStats = await resStats.json();
            
            if (dataStats.status === 'success') {
                updateDashboardCards(dataStats.stats);
                updateChartsData(dataStats);
            }

            // Fetch recent traffic
            const trafficType = document.getElementById('filter-traffic-type').value;
            const resTraffic = await fetch(`/api/traffic?limit=25&attack_type=${trafficType}`);
            const dataTraffic = await resTraffic.json();
            if (dataTraffic.status === 'success') {
                renderTrafficTable(dataTraffic.traffic);
            }

            // Fetch alerts for quick drawer & badge
            const resAlerts = await fetch('/api/alerts?status=ACTIVE&limit=10');
            const dataAlerts = await resAlerts.json();
            if (dataAlerts.status === 'success') {
                renderQuickAlerts(dataAlerts.alerts);
                document.getElementById('nav-alert-badge').textContent = dataAlerts.count;
            }

            // Check live monitoring status
            const resMon = await fetch('/api/monitoring-status');
            const dataMon = await resMon.json();
            if (dataMon.status === 'success') {
                updateMonitoringUI(dataMon.is_monitoring);
            }

        } catch (err) {
            console.error("Error loading dashboard data:", err);
        }
    }

    function updateDashboardCards(stats) {
        document.getElementById('card-total-traffic').textContent = stats.total_traffic.toLocaleString();
        document.getElementById('card-normal-traffic').textContent = stats.normal_traffic.toLocaleString();
        document.getElementById('card-detected-attacks').textContent = stats.detected_attacks.toLocaleString();
        document.getElementById('card-critical-alerts').textContent = stats.critical_alerts.toLocaleString();
    }

    // =========================================================================
    // RENDER TABLES
    // =========================================================================
    
    function renderTrafficTable(trafficList) {
        const tbody = document.querySelector('#table-traffic tbody');
        tbody.innerHTML = '';

        if (!trafficList || trafficList.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#64748b;">No traffic records available. Click "Generate Traffic" to start.</td></tr>';
            return;
        }

        trafficList.forEach(item => {
            const tr = document.createElement('tr');
            const predClass = item.prediction.toLowerCase();
            const badgeClass = `badge-${predClass}`;

            tr.innerHTML = `
                <td>${item.timestamp}</td>
                <td>${item.source_ip}</td>
                <td>${item.destination_ip}</td>
                <td><span class="badge" style="background:rgba(255,255,255,0.06);">${item.protocol}</span></td>
                <td>${item.packet_count}</td>
                <td>${(item.total_bytes / 1024).toFixed(1)} KB</td>
                <td><span class="badge ${badgeClass}">${item.prediction.replace('_', ' ')}</span></td>
                <td>${item.confidence}%</td>
            `;
            tbody.appendChild(tr);
        });
    }

    function renderQuickAlerts(alertsList) {
        const container = document.getElementById('quick-alerts-container');
        container.innerHTML = '';

        if (!alertsList || alertsList.length === 0) {
            container.innerHTML = '<div style="text-align:center; padding:15px; color:#64748b; font-size:12px;">No active alerts. All systems secure.</div>';
            return;
        }

        alertsList.forEach(alert => {
            const div = document.createElement('div');
            div.className = 'quick-alert-item';
            const sevClass = `badge-${alert.severity.toLowerCase()}`;

            div.innerHTML = `
                <div class="quick-alert-head">
                    <span class="badge ${sevClass}">${alert.severity}</span>
                    <span style="font-size:10px; color:#64748b;">${alert.timestamp.split(' ')[1]}</span>
                </div>
                <div style="font-size:12px; font-weight:600; color:#f8fafc; margin-top:2px;">
                    ${alert.attack_type.replace('_', ' ')} from ${alert.source_ip}
                </div>
                <div class="quick-alert-desc">${alert.description}</div>
                <div style="margin-top:4px; text-align:right;">
                    <button class="btn btn-sm btn-secondary btn-resolve" data-id="${alert.id}">Resolve</button>
                </div>
            `;
            container.appendChild(div);
        });

        // Add event listeners for resolve buttons
        container.querySelectorAll('.btn-resolve').forEach(btn => {
            btn.addEventListener('click', async () => {
                const alertId = btn.getAttribute('data-id');
                await resolveAlertApi(alertId);
            });
        });
    }

    async function loadAlertsTable() {
        const attackFilter = document.getElementById('alert-filter-attack').value;
        const sevFilter = document.getElementById('alert-filter-severity').value;
        const statusFilter = document.getElementById('alert-filter-status').value;

        const res = await fetch(`/api/alerts?status=${statusFilter}&severity=${sevFilter}&attack_type=${attackFilter}&limit=100`);
        const data = await res.json();
        
        const tbody = document.querySelector('#table-full-alerts tbody');
        tbody.innerHTML = '';

        if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:#64748b;">No matching intrusion alerts found.</td></tr>';
            return;
        }

        data.alerts.forEach(alert => {
            const tr = document.createElement('tr');
            const sevClass = `badge-${alert.severity.toLowerCase()}`;
            const statusClass = alert.status === 'ACTIVE' ? 'badge-active' : 'badge-resolved';

            tr.innerHTML = `
                <td>#${alert.id}</td>
                <td>${alert.timestamp}</td>
                <td>${alert.source_ip}</td>
                <td><strong>${alert.attack_type.replace('_', ' ')}</strong></td>
                <td><span class="badge ${sevClass}">${alert.severity}</span></td>
                <td>${alert.confidence}%</td>
                <td style="max-width:250px; font-size:11px;">${alert.description}</td>
                <td><span class="badge ${statusClass}">${alert.status}</span></td>
                <td>
                    ${alert.status === 'ACTIVE' ? `<button class="btn btn-sm btn-secondary btn-resolve-table" data-id="${alert.id}">Resolve</button>` : '<span style="color:#64748b; font-size:11px;">Resolved</span>'}
                </td>
            `;
            tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.btn-resolve-table').forEach(btn => {
            btn.addEventListener('click', async () => {
                const id = btn.getAttribute('data-id');
                await resolveAlertApi(id);
                loadAlertsTable();
            });
        });
    }

    async function resolveAlertApi(alertId) {
        try {
            const res = await fetch(`/api/alerts/${alertId}/resolve`, { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                loadDashboardData();
            }
        } catch (err) {
            console.error("Error resolving alert:", err);
        }
    }

    // =========================================================================
    // TRAFFIC ANALYSIS PAGE DATA
    // =========================================================================
    
    async function loadTrafficAnalysis() {
        try {
            const res = await fetch('/api/traffic-analysis');
            const data = await res.json();
            if (data.status === 'success') {
                const ana = data.analysis;
                document.getElementById('ana-avg-packets').textContent = ana.avg_packets;
                document.getElementById('ana-avg-bytes').textContent = `${ana.avg_bytes_sec} B/s`;
                document.getElementById('ana-suspicious-count').textContent = ana.suspicious_sources.length;
                document.getElementById('ana-top-attack').textContent = ana.top_attack.replace('_', ' ');

                // Render Top Sources
                const tbodySources = document.querySelector('#table-top-sources tbody');
                tbodySources.innerHTML = '';
                ana.top_sources.forEach(item => {
                    tbodySources.innerHTML += `<tr><td>${item.source_ip}</td><td>${item.count} flows</td></tr>`;
                });

                // Render Top Dest
                const tbodyDests = document.querySelector('#table-top-dests tbody');
                tbodyDests.innerHTML = '';
                ana.top_destinations.forEach(item => {
                    tbodyDests.innerHTML += `<tr><td>${item.destination_ip}</td><td>${item.count} flows</td></tr>`;
                });
            }
        } catch (err) {
            console.error("Error loading traffic analysis:", err);
        }
    }

    // =========================================================================
    // MODEL PERFORMANCE PAGE DATA
    // =========================================================================
    
    async function loadModelPerformance() {
        try {
            const res = await fetch('/api/model-performance');
            const data = await res.json();
            
            if (data.status === 'success') {
                const m = data.metrics;
                document.getElementById('metric-accuracy').textContent = `${(m.accuracy * 100).toFixed(1)}%`;
                document.getElementById('metric-precision').textContent = `${(m.precision * 100).toFixed(1)}%`;
                document.getElementById('metric-recall').textContent = `${(m.recall * 100).toFixed(1)}%`;
                document.getElementById('metric-f1').textContent = `${(m.f1_score * 100).toFixed(1)}%`;

                document.getElementById('param-train-count').textContent = m.train_samples;
                document.getElementById('param-test-count').textContent = m.test_samples;

                // Render Confusion Matrix
                renderConfusionMatrix(data.classes, data.confusion_matrix);

                // Render Feature Importance Chart
                renderFeatureImportanceChart(data.feature_importances);
            }
        } catch (err) {
            console.error("Error loading model performance:", err);
        }
    }

    function renderConfusionMatrix(classes, cm) {
        const container = document.getElementById('confusion-matrix-grid');
        let html = '<table class="cm-table"><thead><tr><th>Actual \\ Predicted</th>';
        
        classes.forEach(c => {
            html += `<th>${c.replace('_', ' ')}</th>`;
        });
        html += '</tr></thead><tbody>';

        cm.forEach((row, i) => {
            html += `<tr><th>${classes[i].replace('_', ' ')}</th>`;
            row.forEach((val, j) => {
                const cellClass = val > 0 ? 'cm-high' : 'cm-zero';
                html += `<td class="cm-cell ${cellClass}">${val}</td>`;
            });
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    // =========================================================================
    // CHART.JS INITIALIZATION & UPDATES
    // =========================================================================
    
    function initCharts() {
        const chartFont = { family: 'Outfit', size: 11 };

        // Chart 1: Traffic Classification (Doughnut)
        const ctx1 = document.getElementById('chart-traffic-class').getContext('2d');
        charts.trafficClass = new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['NORMAL', 'PORT SCAN', 'DoS', 'BRUTE FORCE'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#10b981', '#f97316', '#ef4444', '#8b5cf6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', font: chartFont } }
                }
            }
        });

        // Chart 2: Traffic Rate Over Time (Line Area)
        const ctx2 = document.getElementById('chart-traffic-time').getContext('2d');
        charts.trafficTime = new Chart(ctx2, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Total Flow Volume',
                        data: [],
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.1)',
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Attack Flow Volume',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8', font: chartFont }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8', font: chartFont }, grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: { legend: { position: 'top', labels: { color: '#94a3b8', font: chartFont } } }
            }
        });

        // Chart 3: Attack Severity Breakdown (Bar)
        const ctx3 = document.getElementById('chart-attack-severity').getContext('2d');
        charts.attackSeverity = new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'High', 'Critical'],
                datasets: [{
                    label: 'Threat Alerts',
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#06b6d4', '#f59e0b', '#f97316', '#ef4444'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8', font: chartFont }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8', font: chartFont }, grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // Chart 4: Protocol Distribution (Doughnut)
        const ctx4 = document.getElementById('chart-protocol-dist').getContext('2d');
        charts.protocolDist = new Chart(ctx4, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#0284c7', '#8b5cf6', '#06b6d4'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: chartFont } } }
            }
        });
    }

    function updateChartsData(apiData) {
        const ad = apiData.attack_distribution;
        
        // Update Chart 1
        charts.trafficClass.data.datasets[0].data = [
            ad.NORMAL || 0,
            ad.PORT_SCAN || 0,
            ad.DOS || 0,
            ad.BRUTE_FORCE || 0
        ];
        charts.trafficClass.update();

        // Update Chart 2
        const tt = apiData.traffic_over_time;
        charts.trafficTime.data.labels = tt.map(item => item.time_slot);
        charts.trafficTime.data.datasets[0].data = tt.map(item => item.total_flows);
        charts.trafficTime.data.datasets[1].data = tt.map(item => item.attack_flows);
        charts.trafficTime.update();

        // Update Chart 3
        const normal = ad.NORMAL || 0;
        const brute = ad.BRUTE_FORCE || 0;
        const pscan = ad.PORT_SCAN || 0;
        const dos = ad.DOS || 0;
        charts.attackSeverity.data.datasets[0].data = [normal, brute, pscan, dos];
        charts.attackSeverity.update();

        // Update Chart 4
        fetch('/api/protocol-distribution')
            .then(res => res.json())
            .then(pdata => {
                if (pdata.status === 'success') {
                    const pd = pdata.protocol_distribution;
                    charts.protocolDist.data.datasets[0].data = [pd.TCP || 0, pd.UDP || 0, pd.ICMP || 0];
                    charts.protocolDist.update();
                }
            });
    }

    function renderFeatureImportanceChart(importancesDict) {
        const ctx = document.getElementById('chart-feature-importance').getContext('2d');
        const sorted = Object.entries(importancesDict).sort((a, b) => b[1] - a[1]);
        
        const labels = sorted.map(item => item[0].replace('_', ' '));
        const values = sorted.map(item => (item[1] * 100).toFixed(1));

        if (charts.featureImp) charts.featureImp.destroy();

        charts.featureImp = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Feature Weight (%)',
                    data: values,
                    backgroundColor: '#8b5cf6',
                    borderRadius: 6
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // =========================================================================
    // MODALS & LIVE MONITORING CONTROLS
    // =========================================================================
    
    function initModals() {
        const modalGen = document.getElementById('modal-generate');
        
        document.getElementById('btn-open-generate').addEventListener('click', () => modalGen.classList.add('show'));
        document.getElementById('btn-close-modal').addEventListener('click', () => modalGen.classList.remove('show'));
        document.getElementById('btn-cancel-modal').addEventListener('click', () => modalGen.classList.remove('show'));

        // Generate submit
        document.getElementById('btn-submit-generate').addEventListener('click', async () => {
            const count = parseInt(document.getElementById('gen-count').value) || 10;
            const attackType = document.getElementById('gen-type').value;

            modalGen.classList.remove('show');

            try {
                const res = await fetch('/api/generate-traffic', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ count: count, attack_type: attackType })
                });
                const data = await res.json();
                if (data.status === 'success') {
                    loadDashboardData();
                }
            } catch (err) {
                console.error("Error generating traffic:", err);
            }
        });

        // Toggle Live Monitoring Button
        const btnToggleMon = document.getElementById('btn-toggle-monitoring');
        btnToggleMon.addEventListener('click', async () => {
            const endpoint = isMonitoring ? '/api/stop-monitoring' : '/api/start-monitoring';
            try {
                const res = await fetch(endpoint, { method: 'POST' });
                const data = await res.json();
                if (data.status === 'success') {
                    updateMonitoringUI(data.is_monitoring);
                }
            } catch (err) {
                console.error("Error toggling monitoring:", err);
            }
        });

        // Filter event listeners on Alerts view
        ['alert-filter-attack', 'alert-filter-severity', 'alert-filter-status'].forEach(id => {
            document.getElementById(id).addEventListener('change', loadAlertsTable);
        });

        // Traffic filter listener
        document.getElementById('filter-traffic-type').addEventListener('change', loadDashboardData);

        // Refresh dashboard button
        document.getElementById('btn-refresh-dashboard').addEventListener('click', loadDashboardData);

        // DEMO MODE DRAWER
        const demoDrawer = document.getElementById('demo-drawer');
        document.getElementById('btn-demo-mode').addEventListener('click', () => demoDrawer.classList.add('show'));
        document.getElementById('btn-close-demo').addEventListener('click', () => demoDrawer.classList.remove('show'));
        document.getElementById('btn-run-demo-flow').addEventListener('click', runDemoScenario);
    }

    function updateMonitoringUI(active) {
        isMonitoring = active;
        const btn = document.getElementById('btn-toggle-monitoring');
        const badgeText = document.getElementById('monitoring-text');
        const dot = document.querySelector('#monitoring-badge .dot');

        if (active) {
            btn.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Monitoring';
            btn.className = 'btn btn-danger';
            badgeText.textContent = 'Monitoring: ACTIVE';
            dot.className = 'dot pulse';
        } else {
            btn.innerHTML = '<i class="fa-solid fa-play"></i> Start Monitoring';
            btn.className = 'btn btn-success';
            badgeText.textContent = 'Monitoring: IDLE';
            dot.className = 'dot idle';
        }
    }

    // =========================================================================
    // DEMO MODE SCENARIO EXECUTION
    // =========================================================================
    
    async function runDemoScenario() {
        const terminal = document.getElementById('demo-terminal-log');
        terminal.innerHTML = '<p class="term-line sys">[DEMO INITIALIZED] Starting intrusion detection workflow...</p>';

        const steps = ['DOS', 'PORT_SCAN', 'BRUTE_FORCE'];
        const randomAttack = steps[Math.floor(Math.random() * steps.length)];

        try {
            const res = await fetch('/api/demo-step', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ step: 1, attack_type: randomAttack })
            });
            const data = await res.json();

            if (data.status === 'success') {
                data.logs.forEach((logLine, idx) => {
                    setTimeout(() => {
                        const p = document.createElement('p');
                        p.className = logLine.includes('ALERT') || logLine.includes('🚨') ? 'term-line alert' : 'term-line';
                        p.textContent = logLine;
                        terminal.appendChild(p);
                        terminal.scrollTop = terminal.scrollHeight;
                        
                        // Highlight step pills
                        const pillId = `pill-step-${Math.min(4, idx + 1)}`;
                        const pill = document.getElementById(pillId);
                        if (pill) pill.classList.add('active');
                    }, idx * 600);
                });

                setTimeout(() => {
                    loadDashboardData();
                }, data.logs.length * 600 + 400);
            }
        } catch (err) {
            console.error("Error executing demo scenario:", err);
        }
    }

    // =========================================================================
    // VIVA ACCORDION
    // =========================================================================
    
    function initAccordion() {
        const items = document.querySelectorAll('.accordion-item');
        items.forEach(item => {
            const header = item.querySelector('.accordion-header');
            header.addEventListener('click', () => {
                const isActive = item.classList.contains('active');
                items.forEach(i => i.classList.remove('active'));
                if (!isActive) item.classList.add('active');
            });
        });
    }

});
