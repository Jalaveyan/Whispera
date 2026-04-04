"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const auth_module_1 = require("./modules/auth/auth.module");
const users_module_1 = require("./modules/users/users.module");
const sessions_module_1 = require("./modules/sessions/sessions.module");
const system_module_1 = require("./modules/system/system.module");
const dashboard_module_1 = require("./modules/dashboard/dashboard.module");
const inbounds_module_1 = require("./modules/inbounds/inbounds.module");
const stats_module_1 = require("./modules/stats/stats.module");
const routing_module_1 = require("./modules/routing/routing.module");
const outbounds_module_1 = require("./modules/outbounds/outbounds.module");
const bridges_module_1 = require("./modules/bridges/bridges.module");
const subscriptions_module_1 = require("./modules/subscriptions/subscriptions.module");
const adblock_module_1 = require("./modules/adblock/adblock.module");
const logs_module_1 = require("./modules/logs/logs.module");
const upload_module_1 = require("./modules/upload/upload.module");
const firewall_module_1 = require("./modules/firewall/firewall.module");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true,
                envFilePath: '.env',
            }),
            auth_module_1.AuthModule,
            users_module_1.UsersModule,
            sessions_module_1.SessionsModule,
            system_module_1.SystemModule,
            dashboard_module_1.DashboardModule,
            inbounds_module_1.InboundsModule,
            stats_module_1.StatsModule,
            routing_module_1.RoutingModule,
            outbounds_module_1.OutboundsModule,
            bridges_module_1.BridgesModule,
            subscriptions_module_1.SubscriptionsModule,
            adblock_module_1.AdblockModule,
            logs_module_1.LogsModule,
            upload_module_1.UploadModule,
            firewall_module_1.FirewallModule,
        ],
    })
], AppModule);
//# sourceMappingURL=app.module.js.map