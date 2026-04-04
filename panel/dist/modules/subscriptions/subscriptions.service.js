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
Object.defineProperty(exports, "__esModule", { value: true });
exports.SubscriptionsService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let SubscriptionsService = class SubscriptionsService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getSubscriptions(token, host = '', proto = 'https') {
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/subscriptions`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'X-Forwarded-Host': host,
                    'X-Forwarded-Proto': proto,
                },
            }));
            return response.data.subscriptions || response.data || [];
        }
        catch (e) {
            if (e.response?.status === 404)
                return [];
            throw e;
        }
    }
    async addSubscription(token, dto, host = '', proto = 'https') {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/subscriptions/add`, dto, {
            headers: {
                Authorization: `Bearer ${token}`,
                'X-Forwarded-Host': host,
                'X-Forwarded-Proto': proto,
            },
        }));
        return response.data.subscription;
    }
    async updateSubscription(token, id, dto) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/subscriptions/update`, { id, ...dto }, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data.subscription;
    }
    async deleteSubscription(token, id) {
        await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/subscriptions/delete`, { id }, { headers: { Authorization: `Bearer ${token}` } }));
    }
    async getSubscriptionContent(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/sub/${token}`, {
            responseType: 'text',
        }));
        return response.data;
    }
};
exports.SubscriptionsService = SubscriptionsService;
exports.SubscriptionsService = SubscriptionsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], SubscriptionsService);
//# sourceMappingURL=subscriptions.service.js.map