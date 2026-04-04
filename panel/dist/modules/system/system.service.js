"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var SystemService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SystemService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
const rxjs_2 = require("rxjs");
let SystemService = SystemService_1 = class SystemService {
    httpService;
    configService;
    logger = new common_1.Logger(SystemService_1.name);
    backendUrl;
    requestTimeout = 10000;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getSystemInfo(token) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/system/info`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to get system info: ${err.message}`);
                return (0, rxjs_2.of)({ data: { version: 'unknown', uptime: 0, go_version: '', server_ip: '', public_key: '' } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`System info error: ${err.message}`);
            return { version: 'unknown', uptime: 0, go_version: '', server_ip: '', public_key: '' };
        }
    }
    async getStats(token) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/stats`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to get stats: ${err.message}`);
                return (0, rxjs_2.of)({ data: { total_users: 0, active_sessions: 0, total_upload: 0, total_download: 0 } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`Stats error: ${err.message}`);
            return { total_users: 0, active_sessions: 0, total_upload: 0, total_download: 0 };
        }
    }
    async reloadConfig(token) {
        try {
            await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/v1/config/reload`, {}, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Failed to reload config: ${err.message}`);
                throw err;
            })));
        }
        catch (err) {
            this.logger.error(`Config reload error: ${err.message}`);
            throw err;
        }
    }
    async getConfig(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v1/config`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async updateConfig(token, config) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/v1/config/update`, config, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async renewCert(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/v1/config/renew-cert`, {}, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async getBackup(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/backup`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 30000,
        }));
        return response.data;
    }
    async restoreBackup(token, backup) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/backup/restore`, backup, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 30000,
        }));
        return response.data;
    }
    async getProbeStats(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/probe/stats`, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async probeBlockIP(token, ip, reason) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/probe/block`, { ip, reason }, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async probeUnblockIP(token, ip) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/probe/unblock`, { ip }, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }));
        return response.data;
    }
    async getHealth() {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/v1/health`, {
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`Health check failed: ${err.message}`);
                return (0, rxjs_2.of)({ data: { healthy: false, error: err.message } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`Health check error: ${err.message}`);
            return { healthy: false, error: err.message };
        }
    }
    async getMLConfig(token) {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/ml/config`, {
                headers: { Authorization: `Bearer ${token}` },
                timeout: this.requestTimeout,
            }).pipe((0, rxjs_1.timeout)(this.requestTimeout), (0, rxjs_1.catchError)(err => {
                this.logger.warn(`ML config fetch failed: ${err.message}`);
                return (0, rxjs_2.of)({ data: { enabled: false, server_url: '', token_set: false } });
            })));
            return response.data;
        }
        catch (err) {
            this.logger.error(`ML config error: ${err.message}`);
            return { enabled: false, server_url: '', token_set: false };
        }
    }
    async rotateMLToken(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/ml/token/rotate`, {}, {
            headers: { Authorization: `Bearer ${token}` },
            timeout: this.requestTimeout,
        }).pipe((0, rxjs_1.timeout)(this.requestTimeout)));
        return response.data;
    }
};
exports.SystemService = SystemService;
exports.SystemService = SystemService = SystemService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], SystemService);
//# sourceMappingURL=system.service.js.map