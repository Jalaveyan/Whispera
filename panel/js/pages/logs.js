import { api } from '../services/api.js';

export const logsPage = {
    async loadLogs() {
        const container = document.getElementById('logs-container');
        container.textContent = 'Загрузка логов...';
        try {
            const data = await api.getLogs(200);
            const logs = data.logs || data || [];
            if (logs.length === 0) {
                container.textContent = 'Нет доступных логов.';
            } else {
                container.textContent = logs.join('\n');
            }
        } catch (error) {
            container.textContent = 'Ошибка загрузки логов: ' + error.message;
        }
    }
};
