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
exports.InboundsService = void 0;
const common_1 = require("@nestjs/common");
const axios_1 = require("@nestjs/axios");
const config_1 = require("@nestjs/config");
const rxjs_1 = require("rxjs");
let InboundsService = class InboundsService {
    httpService;
    configService;
    backendUrl;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }
    async getInbounds(token) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/inbounds`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data.inbounds || response.data || [];
    }
    async addInbound(token, inbound) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/inbounds/add`, inbound, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data;
    }
    async deleteInbound(token, tag) {
        await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/inbounds/delete`, { tag }, { headers: { Authorization: `Bearer ${token}` } }));
    }
    async getPublicKey(token, port) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`${this.backendUrl}/api/inbounds/pubkey?port=${port}`, {
            headers: { Authorization: `Bearer ${token}` },
        }));
        return response.data.public_key || response.data;
    }
    async generateTransportCredentials(token, transport) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/keys/transport`, { transport }, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data.result;
    }
    async generateMultiTransportCredentials(token, transports) {
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.post(`${this.backendUrl}/api/keys/multi-transport`, { transports }, { headers: { Authorization: `Bearer ${token}` } }));
        return response.data.results;
    }
};
exports.InboundsService = InboundsService;
exports.InboundsService = InboundsService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [axios_1.HttpService,
        config_1.ConfigService])
], InboundsService);
//# sourceMappingURL=inbounds.service.js.map