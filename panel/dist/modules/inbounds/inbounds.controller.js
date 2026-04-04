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
exports.InboundsController = void 0;
const common_1 = require("@nestjs/common");
const inbounds_service_1 = require("./inbounds.service");
let InboundsController = class InboundsController {
    inboundsService;
    constructor(inboundsService) {
        this.inboundsService = inboundsService;
    }
    async getInbounds(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const inbounds = await this.inboundsService.getInbounds(token);
            return res.json({ success: true, inbounds });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch inbounds' });
        }
    }
    async addInbound(auth, inbound, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.inboundsService.addInbound(token, inbound);
            return res.json({ success: true, inbound: result });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add inbound' });
        }
    }
    async deleteInbound(auth, tag, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.inboundsService.deleteInbound(token, tag);
            return res.json({ success: true });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete inbound' });
        }
    }
    async getPublicKey(auth, port, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const publicKey = await this.inboundsService.getPublicKey(token, parseInt(port));
            return res.json({ success: true, public_key: publicKey });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to get public key' });
        }
    }
};
exports.InboundsController = InboundsController;
__decorate([
    (0, common_1.Get)('api/inbounds'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], InboundsController.prototype, "getInbounds", null);
__decorate([
    (0, common_1.Post)('api/inbounds'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], InboundsController.prototype, "addInbound", null);
__decorate([
    (0, common_1.Delete)('api/inbounds/:tag'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('tag')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], InboundsController.prototype, "deleteInbound", null);
__decorate([
    (0, common_1.Get)('api/publickey/:port'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('port')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], InboundsController.prototype, "getPublicKey", null);
exports.InboundsController = InboundsController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [inbounds_service_1.InboundsService])
], InboundsController);
//# sourceMappingURL=inbounds.controller.js.map