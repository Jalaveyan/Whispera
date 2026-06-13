import { translations } from './i18n/translations.js';
import { api } from './services/api.js';
import { CustomSelect } from './components/custom-select.js';
import { settingsPage } from './pages/settings.js';
import { dashboardPage } from './pages/dashboard.js';
import { inboundsPage } from './pages/inbounds.js';
import { outboundsPage } from './pages/outbounds.js';
import { routingPage } from './pages/routing.js';
import { subscriptionsPage } from './pages/subscriptions.js';
import { usersPage } from './pages/users.js';
import { bridgesPage } from './pages/bridges.js';
import { sessionsPage } from './pages/sessions.js';
import { logsPage } from './pages/logs.js';
import { firewallPage } from './pages/firewall.js';

class WhisperaApp {
    constructor() {

        this.currentPage = 'dashboard';
        this.translations = translations;
        this.init();
    }

    init() {
        if (api.token) {
            this.showMainApp();
            this.loadDashboard();
        } else {
            this.showLogin();
        }

        this.bindEvents();
        document.addEventListener('click', (e) => {
            const el = e.target.closest('[data-act]');
            if (!el) return;
            const act = el.dataset.act;
            if (act === 'copy') {
                navigator.clipboard.writeText(el.dataset.copy || '').then(() => this.showNotification('Скопировано', 'success')).catch(() => {});
                return;
            }
            if (typeof this[act] === 'function') this[act](el.dataset.arg);
        });
        this.initBackgroundEffects();
        this.initCustomSelects();

        const savedLang = localStorage.getItem('whispera_lang') || 'ru';
        this.applyLanguage(savedLang);

        const savedTheme = localStorage.getItem('whispera_theme') || 'dark';
        this.handleThemeChange(savedTheme);

        if (api.token) {
            const savedPage = localStorage.getItem('whispera_page') || 'dashboard';
            if (savedPage !== 'dashboard') {
                this.navigateTo(savedPage);
            }
        }
    }

    initCustomSelects() {
        document.querySelectorAll('select:not(.custom-select-hidden)').forEach(select => {
            if (select.offsetParent !== null) {
                new CustomSelect(select);
            }
        });
    }

    applyLanguage(lang) {
        if (!this.translations[lang]) lang = 'ru';

        localStorage.setItem('whispera_lang', lang);

        const dictionary = this.translations[lang];
        document.querySelectorAll('[data-i18n]').forEach(element => {
            const key = element.getAttribute('data-i18n');
            if (dictionary[key]) {
                if ((element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') && element.hasAttribute('placeholder')) {
                    element.placeholder = dictionary[key];
                } else {
                    element.textContent = dictionary[key];
                }
            }
        });

        document.querySelectorAll('[data-i18n-label]').forEach(element => {
            const key = element.getAttribute('data-i18n-label');
            if (dictionary[key]) element.label = dictionary[key];
        });

        const rtlLangs = new Set(['fa']);
        document.documentElement.dir = rtlLangs.has(lang) ? 'rtl' : 'ltr';
        document.documentElement.lang = lang;

        if (document.getElementById('panel-language')) {
            document.getElementById('panel-language').value = lang;
        }
    }

    initBackgroundEffects() {
        const savedBg = JSON.parse(localStorage.getItem('whispera_bg') || 'null');
        if (savedBg) {
            this.applyBackground(savedBg.url, savedBg.type);
            document.getElementById('bg-reset-btn').style.display = 'block';
        } else {
            this.applyBackground(null, null);
        }

        const bg = document.querySelector('.bg-gradient');
        if (!bg) return;

        document.addEventListener('mousemove', (e) => {
            const x = (e.clientX / window.innerWidth) * 100;
            const y = (e.clientY / window.innerHeight) * 100;

            bg.style.setProperty('--x', `${x}%`);
            bg.style.setProperty('--y', `${y}%`);
        });
    }

    async handleBackgroundUpload(file) {
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        const status = document.getElementById('bg-upload-status');
        const btn = document.getElementById('bg-upload-btn');
        const originalText = btn.innerHTML;

        try {
            status.textContent = 'Загрузка...';
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';

            const response = await fetch('/api/upload', {
                method: 'POST',
                body: formData,
                headers: {
                    'Authorization': `Bearer ${api.token}`
                }
            });

            if (!response.ok) throw new Error('Upload failed');

            const data = await response.json();

            const bgData = { url: data.url, type: data.type };
            localStorage.setItem('whispera_bg', JSON.stringify(bgData));
            this.applyBackground(data.url, data.type);

            document.getElementById('bg-reset-btn').style.display = 'block';
            status.textContent = 'Успешно!';
            status.style.color = '#4ade80';

            setTimeout(() => status.textContent = '', 3000);

        } catch (error) {
            console.error(error);
            status.textContent = 'Ошибка: ' + error.message;
            status.style.color = '#f87171';
            this.showNotification('Upload Error: ' + error.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
            document.getElementById('bg-upload-input').value = '';
        }
    }

    resetBackground() {
        localStorage.removeItem('whispera_bg');
        this.applyBackground(null, null);
        document.getElementById('bg-reset-btn').style.display = 'none';
        this.showNotification('Фон сброшен', 'success');
    }

    applyBackground(url, type) {
        const bgVideo = document.getElementById('bg-video');
        if (bgVideo) bgVideo.remove();

        const canvas = document.getElementById('city-canvas');
        const bgEffects = document.querySelector('.bg-effects');
        const bgRain = document.querySelector('.bg-rain');

        if (!url) {
            document.body.style.backgroundImage = '';
            document.body.classList.remove('custom-bg-active');

            if (canvas) canvas.style.opacity = '1';
            if (bgEffects) bgEffects.style.display = 'block';
            if (bgRain) bgRain.style.display = 'block';
            return;
        }

        document.body.classList.add('custom-bg-active');

        if (canvas) canvas.style.opacity = '0';
        if (bgEffects) bgEffects.style.display = 'none';
        if (bgRain) bgRain.style.display = 'none';

        if (type === 'video') {
            document.body.style.backgroundImage = '';
            const video = document.createElement('video');
            video.id = 'bg-video';
            video.src = url;
            video.autoplay = true;
            video.loop = true;
            video.muted = true;
            video.playsInline = true;
            video.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; object-fit: cover; z-index: -9999;';
            document.body.appendChild(video);
        } else {
            document.body.style.backgroundImage = `url('${url}')`;
            document.body.style.backgroundSize = 'cover';
            document.body.style.backgroundPosition = 'center';
            document.body.style.backgroundRepeat = 'no-repeat';
            document.body.style.backgroundAttachment = 'fixed';
        }
    }

    async handleLogin() {

        const loginForm = document.getElementById('login-form');
        const username = loginForm.username.value;
        const password = loginForm.password.value;
        const btn = loginForm.querySelector('button');
        const originalText = btn.innerHTML;

        try {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';

            const response = await api.login(username, password);

            if (response.token) {
                api.setToken(response.token);
                this.showMainApp();
                localStorage.setItem('whispera_page', 'dashboard');
                this.navigateTo('dashboard');
                this.showNotification('Welcome back, Commander.', 'success');
            } else {
                throw new Error('Invalid credentials');
            }
        } catch (error) {
            this.showNotification('Access Denied: ' + error.message, 'error');
            const card = document.querySelector('.login-card');
            if (card) {
                card.classList.add('shake');
                setTimeout(() => card.classList.remove('shake'), 500);
            }
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    }

    bindEvents() {
        document.getElementById('login-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.navigateTo(page);
                if (window.innerWidth <= 768) this.closeSidebar();
            });
        });

        document.getElementById('menu-toggle')?.addEventListener('click', () => this.toggleSidebar());
        document.getElementById('sidebar-overlay')?.addEventListener('click', () => this.closeSidebar());

        document.getElementById('logout-btn')?.addEventListener('click', () => {
            this.handleLogout();
        });

        document.getElementById('add-user-btn')?.addEventListener('click', async () => {
            this.showModal('add-user-modal');
            const portField = document.getElementById('new-user-port');
            if (portField) {
                portField.value = '';
                portField.dataset.autoSet = '1';
                portField.addEventListener('input', () => { delete portField.dataset.autoSet; }, { once: true });
            }
            try {
                const data = await api.getInbounds();
                this._cachedInbounds = (data.inbounds || data) || [];
                this._updateUserPort();
            } catch { this._cachedInbounds = []; }
        });

        document.getElementById('add-user-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddUser();
        });

        document.querySelectorAll('.modal-close').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        document.getElementById('force-reload-btn')?.addEventListener('click', async () => {
            try {
                await api.reloadConfig();
                this.showNotification('Конфигурация перезагружена', 'success');
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            }
        });

        document.getElementById('bridges-refresh-btn')?.addEventListener('click', () => {
            this._fetchBridgeStats();
            this._fetchBridgeList();
        });
        document.getElementById('bridges-add-btn')?.addEventListener('click', () => this.showModal('add-bridge-modal'));
        document.getElementById('add-bridge-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fd = new FormData(e.target);
            const submitBtn = e.target.querySelector('button[type="submit"]');
            const origHtml = submitBtn.innerHTML;
            submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Проверка...';
            submitBtn.disabled = true;
            try {
                const res = await api.addBridge({
                    address:    fd.get('address'),
                    region:     fd.get('region'),
                    provider:   fd.get('provider'),
                    type:       fd.get('type'),
                    public_key: fd.get('public_key'),
                });
                this.closeModals();
                e.target.reset();
                if (res && res.is_alive) {
                    this.showNotification(`Мост добавлен ✓ доступен (${res.latency_ms} мс)`, 'success');
                } else if (res && res.id) {
                    this.showNotification('Мост добавлен, но недоступен — проверьте адрес', 'warning');
                } else {
                    this.showNotification('Мост добавлен', 'success');
                }
                await Promise.all([this._fetchBridgeStats(), this._fetchBridgeList()]);
            } catch (err) {
                this.showNotification('Ошибка: ' + err.message, 'error');
            } finally {
                submitBtn.innerHTML = origHtml;
                submitBtn.disabled = false;
            }
        });
        document.getElementById('bridge-copy-token-btn')?.addEventListener('click', () => {
            const token = document.getElementById('bridge-reg-token')?.textContent;
            if (token) navigator.clipboard.writeText(token).then(() => this.showNotification('Токен скопирован', 'success'));
        });
        document.getElementById('bridge-regen-token-btn')?.addEventListener('click', async () => {
            if (!await this.showConfirm('Перегенерировать токен? Все мосты потеряют связь до обновления.')) return;
            try {
                const data = await api.regenerateBridgeToken();
                const el = document.getElementById('bridge-reg-token');
                if (el) el.textContent = data.token || '—';
                this._updateCurlCmd(data.token);
                this.showNotification('Токен обновлён', 'success');
            } catch (e) {
                this.showNotification('Ошибка: ' + e.message, 'error');
            }
        });

        document.getElementById('btn-white-cloudinit')?.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/bridge-white-cloudinit');
                if (!res.ok) throw new Error(await res.text());
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'install-white-bridge.sh';
                a.click();
                URL.revokeObjectURL(url);
                const hint = document.getElementById('white-bridge-install-hint');
                const cmd = document.getElementById('white-bridge-curl-cmd');
                if (hint) hint.style.display = '';
                if (cmd) cmd.textContent = 'bash install-white-bridge.sh';
            } catch (e) {
                this.showNotification('Ошибка: ' + e.message, 'error');
            }
        });

        document.getElementById('add-inbound-btn')?.addEventListener('click', () => this.showModal('add-inbound-modal'));
        document.getElementById('add-inbound-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddInbound();
        });
        document.querySelector('[name="enable_obfuscation"]')?.addEventListener('change', function () {
            const row = document.getElementById('inbound-obfuscation-profile-row');
            if (row) row.style.display = this.checked ? 'flex' : 'none';
        });
        document.querySelector('[name="transport"]')?.addEventListener('change', (e) => {
            this.onInboundTransportChange(e.target.value);
        });
        document.getElementById('transport-checkboxes')?.addEventListener('change', () => {
            const selected = Array.from(document.querySelectorAll('input[name="transport-cb"]:checked')).map(i => i.value);
            this.onKeyTransportChange(selected.length === 1 ? selected[0] : selected);
            this._updateUserPort();
        });

        document.getElementById('add-outbound-btn')?.addEventListener('click', () => {
            this.showModal('add-outbound-modal');
            this._loadBridgesForChainPicker();
        });
        document.getElementById('add-outbound-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddOutbound();
        });

        document.getElementById('add-routing-btn')?.addEventListener('click', () => this.showModal('add-routing-modal'));
        document.getElementById('add-routing-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddRoutingRule();
        });

        document.getElementById('add-subscription-btn')?.addEventListener('click', () => this.showModal('add-subscription-modal'));
        document.getElementById('add-subscription-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAddSubscription();
        });
        document.getElementById('update-subscriptions-btn')?.addEventListener('click', async () => {
            try {
                await api.updateAllSubscriptions();
                this.showNotification('Все подписки обновлены', 'success');
                this.loadSubscriptions();
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            }
        });

        document.getElementById('server-settings-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSaveServerSettings();
        });

        document.getElementById('force-reload-btn')?.addEventListener('click', async () => {
            if (await this.showConfirm('Вы уверены? Это приведет к перезапуску ядра сервера.')) {
                try {
                    await api.reloadConfig();
                    this.showNotification('Ядро успешно перезагружено', 'success');
                } catch (error) {
                    this.showNotification('Ошибка перезагрузки: ' + error.message, 'error');
                }
            }
        });

        document.getElementById('renew-cert-btn')?.addEventListener('click', async () => {
            const btn = document.getElementById('renew-cert-btn');
            const originalContent = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Обновление...';
            btn.disabled = true;
            try {
                await api.renewCertificate();
                this.showNotification('Сертификат успешно обновлен', 'success');
                document.getElementById('ssl-status').textContent = 'Активен (Обновлено)';
                document.getElementById('ssl-expiry').textContent = '2027-01-01';
            } catch (error) {
                this.showNotification('Ошибка: ' + error.message, 'error');
            } finally {
                btn.innerHTML = originalContent;
                btn.disabled = false;
            }
        });

        document.getElementById('firewall-manage-btn')?.addEventListener('click', () => {
            this.showFirewallModal();
        });

        document.getElementById('probe-refresh-btn')?.addEventListener('click', () => this._loadProbeStats());
        document.getElementById('probe-block-btn')?.addEventListener('click', async () => {
            const ip = document.getElementById('probe-block-ip')?.value.trim();
            if (!ip) return;
            try {
                await api.probeBlockIP(ip, 'manual');
                this.showNotification(`IP ${ip} заблокирован`, 'success');
                document.getElementById('probe-block-ip').value = '';
                this._loadProbeStats();
            } catch (e) { this.showNotification('Ошибка: ' + e.message, 'error'); }
        });
        document.getElementById('probe-unblock-btn')?.addEventListener('click', async () => {
            const ip = document.getElementById('probe-unblock-ip')?.value.trim();
            if (!ip) return;
            try {
                await api.probeUnblockIP(ip);
                this.showNotification(`IP ${ip} разблокирован`, 'success');
                document.getElementById('probe-unblock-ip').value = '';
                this._loadProbeStats();
            } catch (e) { this.showNotification('Ошибка: ' + e.message, 'error'); }
        });

        document.getElementById('panel-theme')?.addEventListener('change', (e) => {
            this.handleThemeChange(e.target.value);
        });

        const bgInput = document.getElementById('bg-upload-input');
        if (bgInput) {
            bgInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) this.handleBackgroundUpload(file);
            });
        }

        document.getElementById('bg-reset-btn')?.addEventListener('click', () => {
            this.resetBackground();
        });

        document.getElementById('panel-language')?.addEventListener('change', (e) => {
            this.applyLanguage(e.target.value);
            this.showNotification(e.target.value === 'ru' ? 'Язык изменен' : 'Language changed', 'success');
        });

        document.getElementById('backup-download-btn')?.addEventListener('click', () => this.handleDownloadBackup());

        document.getElementById('backup-upload')?.addEventListener('change', (e) => this.handleRestoreBackup(e));

        document.getElementById('admin-profile-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleUpdateAdminProfile();
        });

        document.getElementById('btn-notifications')?.addEventListener('click', () => {
            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const msg = lang === 'ru' ? 'Нет новых уведомлений' : 'No new notifications';
            this.showNotification(msg, 'info');
        });

        const profileBtn = document.getElementById('btn-profile');
        const profileDropdown = document.getElementById('profile-dropdown');

        if (profileBtn && profileDropdown) {
            profileBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                profileDropdown.classList.toggle('active');
            });

            document.addEventListener('click', (e) => {
                if (!profileBtn.contains(e.target) && !profileDropdown.contains(e.target)) {
                    profileDropdown.classList.remove('active');
                }
            });

            document.getElementById('logout-btn-dropdown')?.addEventListener('click', () => {
                this.handleLogout();
            });

            document.getElementById('settings-btn-dropdown')?.addEventListener('click', () => {
                this.navigateTo('settings');
                profileDropdown?.classList.remove('active');
            });
        }
    }

    handleLogout() {
        api.logout();
        document.getElementById('login-form')?.reset();
        this.showLogin();
    }

    showLogin() {
        document.getElementById('login-screen').classList.add('active');
        document.getElementById('main-app').classList.remove('active');
    }

    showMainApp() {
        document.getElementById('login-screen').classList.remove('active');
        document.getElementById('main-app').classList.add('active');
    }

    navigateTo(page) {
        localStorage.setItem('whispera_page', page);
        if (page !== 'bridges') this._stopBridgeAutoRefresh();

        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
        const navItem = document.querySelector(`.nav-item[data-page="${page}"]`);
        if (navItem) navItem.classList.add('active');

        document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
        const pageEl = document.getElementById(`page-${page}`);
        if (pageEl) {
            pageEl.classList.add('active');

            const titleMap = {
                'dashboard': 'page.dashboard.title',
                'users': 'page.users.title',
                'sessions': 'page.sessions.title',
                'inbounds': 'page.inbounds.title',
                'outbounds': 'page.outbounds.title',
                'routing': 'page.routing.title',
                'subscriptions': 'page.subscriptions.title',
                'bridges': 'page.bridges.title',
                'bridge-map': 'nav.bridge_map',
                'logs': 'page.logs.title',
                'settings': 'settings.title'
            };
            const key = titleMap[page] || 'page.dashboard.title';
            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const dict = this.translations[lang] || this.translations['ru'];
            document.getElementById('page-title').textContent = dict[key] || key;
            document.getElementById('page-title').dataset.i18n = key;
        }

        if (page !== 'dashboard') this.stopLiveStats();

        switch (page) {
            case 'dashboard': this.loadDashboard(); break;
            case 'users': this.loadUsers(); break;
            case 'sessions': this.loadSessions(); break;
            case 'inbounds': this.loadInbounds(); break;
            case 'outbounds': this.loadOutbounds(); break;
            case 'bridges': this.loadBridges(); break;
            case 'bridge-map': this.loadBridgeMap(); break;
            case 'routing': this.loadRouting(); break;
            case 'subscriptions': this.loadSubscriptions(); break;
            case 'settings': this.loadSettings(); break;
            case 'logs': this.loadLogs(); break;
        }
    }

    _relativeTime(date) {
        const diff = Math.floor((Date.now() - date.getTime()) / 1000);
        if (diff < 5)   return 'только что';
        if (diff < 60)  return diff + ' сек. назад';
        if (diff < 3600) return Math.floor(diff / 60) + ' мин. назад';
        if (diff < 86400) return Math.floor(diff / 3600) + ' ч. назад';
        return Math.floor(diff / 86400) + ' д. назад';
    }

    showModal(id) {
        document.getElementById(id)?.classList.add('active');
        const modal = document.getElementById(id);
        if (modal) {
            this.initCustomSelects();
        }
    }

    closeModals() {
        document.querySelectorAll('.modal-backdrop.active').forEach(m => m.classList.remove('active'));
        document.querySelectorAll('.modal.active').forEach(m => m.remove());
    }

    escapeHtml(s) {
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    showNotification(message, type = 'info') {
        const container = document.getElementById('toast-container') || document.body;

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `<span>${this.escapeHtml(message)}</span>`;

        const close = () => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = 'opacity .2s, transform .2s';
            setTimeout(() => toast.remove(), 220);
        };

        toast.addEventListener('click', close);
        setTimeout(close, 5000);
        container.appendChild(toast);
    }

    showConfirm(message) {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'modal-backdrop active';
            modal.style.zIndex = '10000';

            const lang = localStorage.getItem('whispera_lang') || 'ru';
            const textYes = lang === 'ru' ? 'Да' : 'Yes';
            const textNo = lang === 'ru' ? 'Отмена' : 'Cancel';
            const title = lang === 'ru' ? 'Подтверждение' : 'Confirmation';

            modal.innerHTML = `
    <div class="modal" style="max-width:380px;">
        <div class="modal-head">
            <span class="modal-title">${title}</span>
        </div>
        <div class="modal-body" style="font-size:15px;line-height:1.5;">${message}</div>
        <div class="modal-footer">
            <button class="btn btn-secondary" id="confirm-cancel">${textNo}</button>
            <button class="btn btn-danger-solid" id="confirm-ok">${textYes}</button>
        </div>
    </div>`;

            document.body.appendChild(modal);

            const cleanup = () => {
                modal.classList.remove('active');
                setTimeout(() => modal.remove(), 250);
            };

            modal.querySelector('#confirm-cancel').onclick = () => {
                cleanup();
                resolve(false);
            };

            modal.querySelector('#confirm-ok').onclick = () => {
                cleanup();
                resolve(true);
            };

            modal.onclick = (e) => {
                if (e.target === modal) {
                    cleanup();
                    resolve(false);
                }
            };
        });
    }

    toggleSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    }

    closeSidebar() {
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    formatUptime(seconds) {
        if (!seconds) return '-';
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        if (days > 0) return `${days}д ${hours} ч`;
        if (hours > 0) return `${hours}ч ${mins} м`;
        return `${mins} м`;
    }

    formatTime(isoString) {
        if (!isoString) return '-';
        return new Date(isoString).toLocaleString('ru-RU');
    }
}

Object.assign(WhisperaApp.prototype,
  settingsPage, dashboardPage, inboundsPage, outboundsPage, routingPage, subscriptionsPage, usersPage, bridgesPage, sessionsPage, logsPage, firewallPage
);

window.app = new WhisperaApp();
window.escapeHtml = (s) => window.app.escapeHtml(s);
