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
exports.UsersController = void 0;
const common_1 = require("@nestjs/common");
const users_service_1 = require("./users.service");
class CreateUserDto {
    email;
    password;
    traffic_limit;
    valid_until;
    obfs_profile;
    marionette_profile;
    russian_service;
}
let UsersController = class UsersController {
    usersService;
    constructor(usersService) {
        this.usersService = usersService;
    }
    async getUsers(auth, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const users = await this.usersService.getUsers(token);
            return res.json({ success: true, users });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.INTERNAL_SERVER_ERROR;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch users';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async createUser(auth, dto, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.createUser(token, {
                username: dto.email,
                trafficLimit: dto.traffic_limit,
                expiryDate: dto.valid_until,
                obfsProfile: dto.obfs_profile,
                marionetteProfile: dto.marionette_profile,
                russianService: dto.russian_service,
            });
            return res.json({ success: true, user });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to create user';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async updateUser(auth, id, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.updateUser(token, id, {
                username: body.username ?? body.email,
                status: body.status,
                trafficLimit: body.trafficLimit,
                expiryDate: body.expiryDate,
                obfsProfile: body.obfsProfile,
                russianService: body.russianService,
                marionetteProfile: body.marionetteProfile,
            });
            return res.json({ success: true, user });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update user';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async deleteUser(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.usersService.deleteUser(token, id);
            return res.json({ success: true });
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete user';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async generateConnectionKey(auth, body, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.usersService.generateConnectionKey(token, body);
            return res.json(result);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to generate key';
            return res.status(status).json({ success: false, error: msg });
        }
    }
    async getUserStats(auth, id, res) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.usersService.getUserStats(token, id);
            return res.json(stats);
        }
        catch (err) {
            const status = err?.response?.status || common_1.HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch stats';
            return res.status(status).json({ success: false, error: msg });
        }
    }
};
exports.UsersController = UsersController;
__decorate([
    (0, common_1.Get)('api/users'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "getUsers", null);
__decorate([
    (0, common_1.Post)('api/users'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, CreateUserDto, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "createUser", null);
__decorate([
    (0, common_1.Put)('api/users/:id'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Body)()),
    __param(3, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "updateUser", null);
__decorate([
    (0, common_1.Delete)('api/users/:id'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "deleteUser", null);
__decorate([
    (0, common_1.Post)('api/keys/connection'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "generateConnectionKey", null);
__decorate([
    (0, common_1.Get)('api/users/:id/stats'),
    __param(0, (0, common_1.Headers)('authorization')),
    __param(1, (0, common_1.Param)('id')),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "getUserStats", null);
exports.UsersController = UsersController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [users_service_1.UsersService])
], UsersController);
//# sourceMappingURL=users.controller.js.map