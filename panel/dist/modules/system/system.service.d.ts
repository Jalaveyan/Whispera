import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface SystemInfo {
    version: string;
    uptime: number;
    go_version: string;
    server_ip: string;
    public_key: string;
}
export interface SystemStats {
    total_users: number;
    active_sessions: number;
    total_upload: number;
    total_download: number;
}
export declare class SystemService {
    private readonly httpService;
    private readonly configService;
    private readonly logger;
    private readonly backendUrl;
    private readonly requestTimeout;
    constructor(httpService: HttpService, configService: ConfigService);
    getSystemInfo(token: string): Promise<SystemInfo>;
    getStats(token: string): Promise<SystemStats>;
    reloadConfig(token: string): Promise<void>;
    getConfig(token: string): Promise<any>;
    updateConfig(token: string, config: any): Promise<any>;
    renewCert(token: string): Promise<any>;
    getBackup(token: string): Promise<any>;
    restoreBackup(token: string, backup: any): Promise<any>;
    getProbeStats(token: string): Promise<any>;
    probeBlockIP(token: string, ip: string, reason: string): Promise<any>;
    probeUnblockIP(token: string, ip: string): Promise<any>;
    getHealth(): Promise<any>;
    getMLConfig(token: string): Promise<any>;
    rotateMLToken(token: string): Promise<any>;
}
