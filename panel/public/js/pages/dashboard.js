import { api } from '../services/api.js';

export const dashboardPage = {
    async loadDashboard() {
        // Load static server info once (version, IP, OS — doesn't change)
        try {
            const info = await api.getSystemInfo().catch(() => ({}));
            document.getElementById('stat-memory').textContent = info.memory_usage || '-';
            document.getElementById('stat-cpu').textContent = info.cpu_load != null ? info.cpu_load.toFixed(1) + '%' : '-';
            document.getElementById('server-version').textContent = info.version || '-';
            document.getElementById('server-ip').textContent = info.server_ip || '-';
            document.getElementById('server-uptime').textContent = this.formatUptime(info.uptime || 0);
            document.getElementById('server-os').textContent = info.os || '-';
            document.getElementById('server-arch').textContent = info.arch || '-';
        } catch (error) {
            console.error('Dashboard load error:', error);
        }

        this.startLiveStats();
    },
    startLiveStats() {
        this.stopLiveStats();
        this._prevRx = null;
        this._prevTx = null;
        this._prevTs = null;
        const base = (typeof api !== 'undefined' && api.baseURL) ? api.baseURL.replace(/\/$/, '') : '';
        const token = (typeof api !== 'undefined' && api.token) ? encodeURIComponent(api.token) : '';
        const url = base + '/api/stats/live' + (token ? '?token=' + token : '');
        this._liveStatsESrc = new EventSource(url);
        this._liveStatsESrc.onmessage = (e) => {
            try {
                const d = JSON.parse(e.data);
                const el = (id) => document.getElementById(id);
                if (el('stat-users')) el('stat-users').textContent = d.total_users ?? 0;
                if (el('stat-sessions')) el('stat-sessions').textContent = d.active_sessions ?? 0;
                if (el('stat-upload')) el('stat-upload').textContent = this.formatBytes(d.total_upload ?? 0);
                if (el('stat-download')) el('stat-download').textContent = this.formatBytes(d.total_download ?? 0);
                if (el('stat-memory')) el('stat-memory').textContent = d.memory_usage || '-';
                if (el('stat-cpu')) el('stat-cpu').textContent = d.cpu_load != null ? d.cpu_load.toFixed(1) + '%' : '-';
                if (el('server-uptime')) el('server-uptime').textContent = this.formatUptime(d.uptime ?? 0);

                const now = Date.now();
                const rx = d.total_download ?? 0;
                const tx = d.total_upload ?? 0;
                if (this._prevRx !== null && this._prevTs !== null) {
                    const dt = (now - this._prevTs) / 1000;
                    const dlMBs = Math.max(0, (rx - this._prevRx) / dt / (1024 * 1024));
                    const ulMBs = Math.max(0, (tx - this._prevTx) / dt / (1024 * 1024));
                    this.updateTrafficChart(dlMBs, ulMBs);
                }
                this._prevRx = rx;
                this._prevTx = tx;
                this._prevTs = now;
            } catch (_) {}
        };
        this._liveStatsESrc.onerror = () => {};
    },
    stopLiveStats() {
        if (this._liveStatsESrc) {
            this._liveStatsESrc.close();
            this._liveStatsESrc = null;
        }
    },
    initTrafficChart() {
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        this.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: Array(10).fill(''),
                datasets: [{
                    label: 'Download',
                    data: Array(10).fill(0),
                    borderColor: '#06b6d4',
                    backgroundColor: 'rgba(6, 182, 212, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }, {
                    label: 'Upload',
                    data: Array(10).fill(0),
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8' }
                    }
                },
                scales: {
                    y: {
                        min: 0,
                        grid: { color: '#334155' },
                        ticks: {
                            color: '#94a3b8',
                            callback: (v) => v.toFixed(2)
                        }
                    },
                    x: {
                        grid: { display: false }
                    }
                },
                animation: { duration: 800, easing: 'easeOutQuart' }
            }
        });
    },
    updateTrafficChart(download, upload) {
        if (!this.trafficChart) this.initTrafficChart();

        const data = this.trafficChart.data;

        data.datasets[0].data.shift();
        data.datasets[1].data.shift();

        data.datasets[0].data.push(download);
        data.datasets[1].data.push(upload);

        this.trafficChart.update();
    }
};
