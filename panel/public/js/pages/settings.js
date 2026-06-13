import { api } from '../services/api.js';

export const settingsPage = {
    async handleUpdateAdminProfile() {
        const email = document.getElementById('admin-profile-email').value;
        const password = document.getElementById('admin-profile-password').value;

        if (!email) {
            this.showNotification('Email обязателен', 'error');
            return;
        }

        try {
            await api.updateAdminProfile(email, password);
            this.showNotification('Профиль администратора обновлен', 'success');
            localStorage.setItem('whispera_email', email);
            document.getElementById('admin-profile-password').value = '';
        } catch (error) {
            this.showNotification('Ошибка обновления профиля: ' + error.message, 'error');
        }
    },
    async _loadProbeStats() {
        try {
            const s = await api.getProbeStats();
            const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
            set('probe-stat-blocked', s.blocked_ips ?? '—');
            set('probe-stat-tracked', s.tracked_ips ?? '—');
            set('probe-stat-dns',     s.require_dns   ? `вкл (лог: ${s.dns_log_size ?? 0})` : 'выкл');
            set('probe-stat-sni',     s.check_sni_own ? `вкл (${(s.own_ips ?? []).join(', ')})` : 'выкл');
        } catch (e) {
        }
    },
    async handleSaveServerSettings() {
        const port = document.getElementById('server-port').value;
        const domain = document.getElementById('server-domain').value;
        const email = document.getElementById('admin-contact').value;
        const publicURL = (document.getElementById('public-url')?.value || '').trim();

        localStorage.setItem('whispera_domain', domain);
        localStorage.setItem('whispera_admin_email', email);

        try {
            await api.request('/api/v1/config/update', {
                method: 'POST',
                body: JSON.stringify({
                    server: { port: parseInt(port) || 0, public_url: publicURL }
                })
            });
            this.showNotification('Настройки успешно сохранены', 'success');
        } catch (error) {
            this.showNotification('Ошибка сохранения: ' + error.message, 'error');
        }
    },
    handleThemeChange(theme) {
        localStorage.setItem('whispera_theme', theme);
        document.documentElement.setAttribute('data-theme', theme || 'dark');
        this.showNotification('Тема обновлена', 'success');
    },
    async handleDownloadBackup() {
        try {
            const data = await api.getBackup();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `whispera - backup - ${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            this.showNotification('Скачивание началось', 'success');
        } catch (error) {
            this.showNotification('Ошибка создания бэкапа: ' + error.message, 'error');
        }
    },
    async handleRestoreBackup(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (await this.showConfirm('Восстановление перезапишет текущие настройки. Продолжить?')) {
            try {
                await api.restoreBackup(file);
                this.showNotification('Настройки восстановлены! Перезагрузка...', 'success');
                setTimeout(() => window.location.reload(), 2000);
            } catch (error) {
                this.showNotification('Ошибка восстановления: ' + error.message, 'error');
            }
        }
        event.target.value = '';
    },
    async loadSettings() {
        const domain = localStorage.getItem('whispera_domain') || '';
        const email = localStorage.getItem('whispera_admin_email') || '';
        const theme = localStorage.getItem('whispera_theme') || 'dark';
        const lang = localStorage.getItem('whispera_lang') || 'ru';

        if (document.getElementById('server-domain')) document.getElementById('server-domain').value = domain;
        if (document.getElementById('admin-contact')) document.getElementById('admin-contact').value = email;
        if (document.getElementById('panel-theme')) document.getElementById('panel-theme').value = theme;
        if (document.getElementById('panel-language')) document.getElementById('panel-language').value = lang;

        this.initCustomSelects();

        const loginEmail = localStorage.getItem('whispera_email') || '';
        if (document.getElementById('admin-profile-email')) document.getElementById('admin-profile-email').value = loginEmail;

        try {
            const info = await api.getSystemInfo();
            if (info.server_port && document.getElementById('server-port')) {
                document.getElementById('server-port').value = info.server_port;
            }
            if (info.ssl_expiry) {
                const sslExpiry = document.getElementById('ssl-expiry');
                if (sslExpiry) sslExpiry.textContent = info.ssl_expiry;
            }
            if (info.ssl_status) {
                const sslStatus = document.getElementById('ssl-status');
                if (sslStatus) sslStatus.textContent = info.ssl_status === 'active' ? 'Активен' : 'Нет сертификата';
            }
        } catch (e) {
            console.log('Failed to load system info for settings');
        }

        try {
            const cfg = await api.request('/api/v1/config');
            const puInput = document.getElementById('public-url');
            if (puInput) puInput.value = cfg.public_url || '';
        } catch (e) {
            console.log('Failed to load config');
        }

        this._loadProbeStats();
    }
};
