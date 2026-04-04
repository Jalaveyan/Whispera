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
exports.SubscriptionsController = void 0;
const common_1 = require("@nestjs/common");
const subscriptions_service_1 = require("./subscriptions.service");
let SubscriptionsController = class SubscriptionsController {
    subscriptionsService;
    constructor(subscriptionsService) {
        this.subscriptionsService = subscriptionsService;
    }
    async getSubscriptions(auth, req, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const host = req.headers['x-forwarded-host'] || req.headers['host'] || '';
            const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
            const subscriptions = await this.subscriptionsService.getSubscriptions(token, host, proto);
            return res.json({ success: true, subscriptions });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch subscriptions';
            return res.status(err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }
    async addSubscription(auth, dto, req, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const host = req.headers['x-forwarded-host'] || req.headers['host'] || '';
            const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
            const result = await this.subscriptionsService.addSubscription(token, dto, host, proto);
            return res.json({ success: true, subscription: result });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to add subscription';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
    async updateSubscription(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const { id, ...dto } = body;
            const result = await this.subscriptionsService.updateSubscription(token, id, dto);
            return res.json({ success: true, subscription: result });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update subscription';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
    async deleteSubscription(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.subscriptionsService.deleteSubscription(token, id);
            return res.json({ success: true });
        }
        catch (err) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete subscription';
            return res.status(err?.response?.status || common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }
    async updateAll(auth, res) {
        void auth;
        return res.json({ success: true });
    }
    async serveSubscription(token, res) {
        try {
            const content = await this.subscriptionsService.getSubscriptionContent(token);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="whispera-sub.txt"');
            res.setHeader('Profile-Update-Interval', '24');
            return res.send(content);
        }
        catch (err) {
            return res.status(err?.response?.status || common_1.HttpStatus.NOT_FOUND).send('Not Found');
        }
    }
};
exports.SubscriptionsController = SubscriptionsController;
__decorate([
    (0, common_1.Get)('api/subscriptions'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Req)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "getSubscriptions", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/add'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Req)()),
    __param(3, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "addSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/update'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "updateSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/delete'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "deleteSubscription", null);
__decorate([
    (0, common_1.Post)('api/subscriptions/update-all'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "updateAll", null);
__decorate([
    (0, common_1.Get)('sub/:token'),
    __param(0, (0, common_1.Param)('token')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], SubscriptionsController.prototype, "serveSubscription", null);
exports.SubscriptionsController = SubscriptionsController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [subscriptions_service_1.SubscriptionsService])
], SubscriptionsController);
//# sourceMappingURL=subscriptions.controller.js.map