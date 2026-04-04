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
exports.RoutingController = void 0;
const common_1 = require("@nestjs/common");
const routing_service_1 = require("./routing.service");
let RoutingController = class RoutingController {
    routingService;
    constructor(routingService) {
        this.routingService = routingService;
    }
    async getRules(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const rules = await this.routingService.getRules(token);
            return res.json({ success: true, rules });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch routing rules';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async addRule(auth, rule, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.routingService.addRule(token, rule);
            return res.json({ success: true, rule: result });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to add routing rule';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async deleteRule(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.routingService.deleteRule(token, id);
            return res.json({ success: true });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete routing rule';
            return res.status(status).json({ success: false, error: msg });
        }
    }
};
exports.RoutingController = RoutingController;
__decorate([
    (0, common_1.Get)('api/routing/rules'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], RoutingController.prototype, "getRules", null);
__decorate([
    (0, common_1.Post)('api/routing/rules'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], RoutingController.prototype, "addRule", null);
__decorate([
    (0, common_1.Delete)('api/routing/rules/:id'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], RoutingController.prototype, "deleteRule", null);
exports.RoutingController = RoutingController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [routing_service_1.RoutingService])
], RoutingController);
//# sourceMappingURL=routing.controller.js.map