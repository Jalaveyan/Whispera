"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@nestjs/core");
const common_1 = require("@nestjs/common");
const app_module_1 = require("./app.module");
const path_1 = require("path");
const fs_1 = require("fs");
const http = __importStar(require("http"));
const express = __importStar(require("express"));
async function bootstrap() {
    const tlsCertPath = process.env.TLS_CERT;
    const tlsKeyPath = process.env.TLS_KEY;
    let httpsOptions;
    if (tlsCertPath && tlsKeyPath && (0, fs_1.existsSync)(tlsCertPath) && (0, fs_1.existsSync)(tlsKeyPath)) {
        httpsOptions = {
            cert: (0, fs_1.readFileSync)(tlsCertPath),
            key: (0, fs_1.readFileSync)(tlsKeyPath),
        };
    }
    const app = await core_1.NestFactory.create(app_module_1.AppModule, httpsOptions ? { httpsOptions } : {});
    app.useGlobalPipes(new common_1.ValidationPipe({
        transform: true,
    }));
    const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:3000';
    app.enableCors({
        origin: corsOrigin.split(',').map(o => o.trim()),
        credentials: true,
    });
    const publicPath = (0, path_1.join)(__dirname, '..', 'public');
    app.use(express.static(publicPath));
    const httpAdapter = app.getHttpAdapter();
    httpAdapter.get('*', (req, res, next) => {
        if (req.url.startsWith('/api/')) {
            return next();
        }
        res.sendFile((0, path_1.join)(publicPath, 'index.html'));
    });
    const port = process.env.PORT || 3000;
    const host = process.env.LISTEN_HOST || '127.0.0.1';
    await app.listen(port, host);
    const proto = httpsOptions ? 'https' : 'http';
    console.log(`Whispera Panel running on ${proto}://localhost:${port}`);
    if (httpsOptions) {
        const httpPort = parseInt(process.env.HTTP_PORT || '80', 10);
        const httpsPort = String(port);
        http.createServer((req, res) => {
            const host = (req.headers.host || '').replace(/:\d+$/, '');
            res.writeHead(301, { Location: `https://${host}:${httpsPort}${req.url}` });
            res.end();
        }).listen(httpPort, () => {
            console.log(`HTTP→HTTPS redirect on port ${httpPort}`);
        });
    }
}
bootstrap();
//# sourceMappingURL=main.js.map