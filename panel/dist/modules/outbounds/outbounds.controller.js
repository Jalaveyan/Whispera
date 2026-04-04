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
exports.OutboundsController = void 0;
const common_1 = require("@nestjs/common");
const outbounds_service_1 = require("./outbounds.service");
let OutboundsController = class OutboundsController {
    outboundsService;
    constructor(outboundsService) {
        this.outboundsService = outboundsService;
    }
    async getOutbounds(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const outbounds = await this.outboundsService.getOutbounds(token);
            return res.json({ success: true, outbounds });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch outbounds' });
        }
    }
    async addOutbound(auth, outbound, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.outboundsService.addOutbound(token, outbound);
            return res.json({ success: true, outbound: result });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add outbound' });
        }
    }
    async deleteOutbound(auth, tag, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.outboundsService.deleteOutbound(token, tag);
            return res.json({ success: true });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete outbound' });
        }
    }
};
exports.OutboundsController = OutboundsController;
__decorate([
    (0, common_1.Get)('api/outbounds'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], OutboundsController.prototype, "getOutbounds", null);
__decorate([
    (0, common_1.Post)('api/outbounds'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], OutboundsController.prototype, "addOutbound", null);
__decorate([
    (0, common_1.Post)('api/outbounds/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('tag')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], OutboundsController.prototype, "deleteOutbound", null);
exports.OutboundsController = OutboundsController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [outbounds_service_1.OutboundsService])
], OutboundsController);
//# sourceMappingURL=outbounds.controller.js.map