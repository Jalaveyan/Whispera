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
exports.StatsController = void 0;
const common_1 = require("@nestjs/common");
const stats_service_1 = require("./stats.service");
let StatsController = class StatsController {
    statsService;
    constructor(statsService) {
        this.statsService = statsService;
    }
    async getTrafficStats(auth, period, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.statsService.getTrafficStats(token, period || '24h');
            return res.json({ success: true, ...stats });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch traffic stats' });
        }
    }
    async getUserTraffic(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const users = await this.statsService.getUserTraffic(token);
            return res.json({ success: true, users });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch user traffic' });
        }
    }
    async getChartData(auth, period, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const data = await this.statsService.getChartData(token, period || '24h');
            return res.json({ success: true, ...data });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch chart data' });
        }
    }
};
exports.StatsController = StatsController;
__decorate([
    (0, common_1.Get)('api/stats/traffic'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Query)('period')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], StatsController.prototype, "getTrafficStats", null);
__decorate([
    (0, common_1.Get)('api/stats/users'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], StatsController.prototype, "getUserTraffic", null);
__decorate([
    (0, common_1.Get)('api/stats/chart'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Query)('period')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], StatsController.prototype, "getChartData", null);
exports.StatsController = StatsController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [stats_service_1.StatsService])
], StatsController);
//# sourceMappingURL=stats.controller.js.map