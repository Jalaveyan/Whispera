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
exports.AdblockController = void 0;
const common_1 = require("@nestjs/common");
const adblock_service_1 = require("./adblock.service");
let AdblockController = class AdblockController {
    adblockService;
    constructor(adblockService) {
        this.adblockService = adblockService;
    }
    async getStats(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.adblockService.getStats(token);
            return res.json(stats);
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch adblock stats';
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }
    async getRules(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const rules = await this.adblockService.getRules(token);
            return res.json({ success: true, rules });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch adblock rules';
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }
    async addRule(auth, rule, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.adblockService.addRule(token, rule);
            return res.json({ success: true, rule: result });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to add rule';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
    async deleteRule(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.adblockService.deleteRule(token, id);
            return res.json({ success: true });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete rule';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
    async updateSettings(auth, settings, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.adblockService.updateSettings(token, settings);
            return res.json({ success: true });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update settings';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
};
exports.AdblockController = AdblockController;
__decorate([
    (0, common_1.Get)('api/adblock/stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], AdblockController.prototype, "getStats", null);
__decorate([
    (0, common_1.Get)('api/adblock/rules'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], AdblockController.prototype, "getRules", null);
__decorate([
    (0, common_1.Post)('api/adblock/rules/add'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], AdblockController.prototype, "addRule", null);
__decorate([
    (0, common_1.Post)('api/adblock/rules/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], AdblockController.prototype, "deleteRule", null);
__decorate([
    (0, common_1.Post)('api/adblock/settings'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], AdblockController.prototype, "updateSettings", null);
exports.AdblockController = AdblockController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [adblock_service_1.AdblockService])
], AdblockController);
//# sourceMappingURL=adblock.controller.js.map