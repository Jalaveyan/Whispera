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
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
class LoginDto {
    username;
    password;
}
class RegisterDto {
    email;
    password;
}
let AuthController = class AuthController {
    authService;
    constructor(authService) {
        this.authService = authService;
    }
    loginPage(res) {
        return res.redirect('/');
    }
    async login(dto, res) {
        try {
            const result = await this.authService.login(dto.username, dto.password);
            const maxAge = (result.expires_in || 1800) * 1000;
            res.cookie('token', result.token, {
                httpOnly: true,
                sameSite: 'strict',
                maxAge,
                secure: false,
            });
            return res.json({
                success: true,
                token: result.token,
                expires_in: result.expires_in || 1800,
                user: result.user,
            });
        }
        catch (err) {
            if (err?.response?.status === 429) {
                return res.status(429).json({ success: false, error: 'Too many login attempts. Please wait 1 minute.' });
            }
            return res.status(common_1.HttpStatus.UNAUTHORIZED).json({ success: false, error: 'Invalid credentials' });
        }
    }
    async register(dto, res) {
        try {
            const result = await this.authService.registerUser(dto.email, dto.password);
            return res.json(result);
        }
        catch {
            return res.status(common_1.HttpStatus.BAD_REQUEST).json({ success: false, error: 'Registration failed' });
        }
    }
    logout(res) {
        res.clearCookie('token');
        return res.json({ success: true });
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Get)('login'),
    __param(0, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "loginPage", null);
__decorate([
    (0, common_1.Post)('api/auth/login'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [LoginDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('api/auth/register'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [RegisterDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('api/auth/logout'),
    __param(0, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "logout", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], AuthController);
//# sourceMappingURL=auth.controller.js.map