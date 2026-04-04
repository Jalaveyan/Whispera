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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SystemController = void 0;
const common_1 = require("@nestjs/common");
const system_service_1 = require("./system.service");
let SystemController = class SystemController {
    systemService;
    constructor(systemService) {
        this.systemService = systemService;
    }
    async getSystemInfo(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const info = await this.systemService.getSystemInfo(token);
            return res.json(info);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch system info' });
        }
    }
    async getStats(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.systemService.getStats(token);
            return res.json(stats);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch stats' });
        }
    }
    async reloadConfig(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.systemService.reloadConfig(token);
            return res.json({ success: true, message: 'Config reloaded' });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to reload config' });
        }
    }
    async getHealth(res) {
        try {
            const health = await this.systemService.getHealth();
            return res.json(health);
        }
        catch {
            return res.status(common_1.HttpStatus.SERVICE_UNAVAILABLE).json({ status: 'unavailable' });
        }
    }
    async getConfig(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getConfig(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async updateConfig(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.updateConfig(token, body);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async getBackup(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getBackup(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async restoreBackup(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.restoreBackup(token, body);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async renewCert(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.renewCert(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async getProbeStats(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getProbeStats(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.SERVICE_UNAVAILABLE)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async probeBlock(auth, ip, reason, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.probeBlockIP(token, ip, reason || 'manual');
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async probeUnblock(auth, ip, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.probeUnblockIP(token, ip);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message });
        }
    }
    async getMLConfig(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.getMLConfig(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async rotateMLToken(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.systemService.rotateMLToken(token);
            return res.json(data);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR)
                .json({ error: err?.response?.data?.error || err?.message || 'Failed' });
        }
    }
    async generateQR(data, res) {
        if (!data) {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ error: 'data param required' });
        }
        try {
            const QRCode = require('qrcode');
            const url = await QRCode.toDataURL(data, {
                width: 220,
                margin: 2,
                errorCorrectionLevel: 'L',
                color: { dark: '#000000', light: '#ffffff' },
            });
            return res.json({ url });
        }
        catch (err) {
            return res.status(common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ error: err?.message || 'QR generation failed' });
        }
    }
};
exports.SystemController = SystemController;
__decorate([
    (0, common_1.Get)('api/system/info'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getSystemInfo", null);
__decorate([
    (0, common_1.Get)('api/stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getStats", null);
__decorate([
    (0, common_1.Post)('api/system/reload'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "reloadConfig", null);
__decorate([
    (0, common_1.Get)('api/health'),
    __param(0, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getHealth", null);
__decorate([
    (0, common_1.Get)('api/v1/config'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getConfig", null);
__decorate([
    (0, common_1.Post)('api/v1/config/update'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "updateConfig", null);
__decorate([
    (0, common_1.Get)('api/backup'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getBackup", null);
__decorate([
    (0, common_1.Post)('api/backup/restore'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "restoreBackup", null);
__decorate([
    (0, common_1.Post)('api/v1/config/renew-cert'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "renewCert", null);
__decorate([
    (0, common_1.Get)('api/probe/stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getProbeStats", null);
__decorate([
    (0, common_1.Post)('api/probe/block'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('ip')),
    __param(2, (0, common_1.Body)('reason')),
    __param(3, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "probeBlock", null);
__decorate([
    (0, common_1.Post)('api/probe/unblock'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('ip')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "probeUnblock", null);
__decorate([
    (0, common_1.Get)('api/ml/config'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "getMLConfig", null);
__decorate([
    (0, common_1.Post)('api/ml/token/rotate'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "rotateMLToken", null);
__decorate([
    (0, common_1.Get)('api/qr'),
    __param(0, (0, common_1.Query)('data')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SystemController.prototype, "generateQR", null);
exports.SystemController = SystemController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [system_service_1.SystemService])
], SystemController);
//# sourceMappingURL=system.controller.js.map