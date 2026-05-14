import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface DashboardData {
    stats: {
        total_users: number;
        active_sessions: number;
        total_upload: number;
        total_download: number;
    };
    systemInfo: {
        version: string;
        uptime: number;
        server_ip: string;
    };
    recentActivity: any[];
}

@Injectable()
export class DashboardService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getDashboardData(token: string): Promise<DashboardData> {
        const [statsRes, infoRes] = await Promise.all([
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            ).catch(() => ({ data: {} })),
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/system/info`, {
                    headers: { Authorization: `Bearer ${token}` },
                }),
            ).catch(() => ({ data: {} })),
        ]);

        return {
            stats: statsRes.data,
            systemInfo: infoRes.data,
            recentActivity: statsRes.data?.recentActivity || [],
        };
    }

    async getDashboardStats(token: string): Promise<Record<string, unknown>> {
        const headers = { Authorization: `Bearer ${token}` };
        const [statsRes, bridgesRes] = await Promise.all([
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats`, { headers }),
            ).catch(() => ({ data: {} })),
            firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/bridge-admin`, { headers }),
            ).catch(() => ({ data: {} })),
        ]);

        const s = statsRes.data as Record<string, number>;
        const totalBytes = (s.total_upload ?? 0) + (s.total_download ?? 0);
        const bridges: unknown[] = bridgesRes.data?.bridges ?? bridgesRes.data ?? [];

        return {
            users:           s.total_users ?? 0,
            active_sessions: s.active_sessions ?? 0,
            bridges:         Array.isArray(bridges) ? bridges.length : 0,
            total_traffic:   formatBytes(totalBytes),
        };
    }
}

function formatBytes(bytes: number): string {
    if (bytes >= 1e9)  return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6)  return `${(bytes / 1e6).toFixed(1)} MB`;
    if (bytes >= 1e3)  return `${(bytes / 1e3).toFixed(1)} KB`;
    return `${bytes} B`;
}
