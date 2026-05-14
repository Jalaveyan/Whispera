import { Injectable, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

export interface TrafficStats {
    total_upload: number;
    total_download: number;
    total_traffic: number;
    active_users: number;
    user_stats: UserTrafficStats[];
    chart_data?: ChartData;
}

export interface UserTrafficStats {
    user_id: string;
    name: string;
    upload: number;
    download: number;
    total: number;
    limit: number;
    used_percent: number;
}

export interface ChartData {
    labels: string[];
    upload: number[];
    download: number[];
}

@Injectable()
export class StatsService {
    private readonly logger = new Logger(StatsService.name);
    private readonly backendUrl: string;
    private readonly requestTimeout = 10000;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getTrafficStats(token: string, period = '24h'): Promise<TrafficStats> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats/traffic`, {
                    headers: { Authorization: `Bearer ${token}` },
                    params: { period },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError((err: Error) => {
                        this.logger.warn(`Failed to get traffic stats: ${err.message}`);
                        return of({ data: {} });
                    }),
                ),
            );
            const d = response.data as Record<string, unknown>;
            // Map Go field names → SPA field names
            return {
                total_rx:  d.total_download ?? 0,
                total_tx:  d.total_upload   ?? 0,
                sessions:  d.active_users   ?? 0,
                avg_rate:  '—',
            } as unknown as TrafficStats;
        } catch (err) {
            this.logger.error(`Traffic stats error: ${(err as Error).message}`);
            return { total_upload: 0, total_download: 0, total_traffic: 0, active_users: 0, user_stats: [] };
        }
    }

    async getUserTraffic(token: string): Promise<UserTrafficStats[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/users`, {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError((err: Error) => {
                        this.logger.warn(`Failed to get user traffic: ${err.message}`);
                        return of({ data: { users: [] } });
                    }),
                ),
            );
            const users: Record<string, unknown>[] = response.data?.users ?? response.data ?? [];
            return users.map(u => ({
                username: u.username,
                traffic:  ((u.upload as number) ?? 0) + ((u.download as number) ?? 0),
                sessions: 0,
            })) as unknown as UserTrafficStats[];
        } catch (err) {
            this.logger.error(`User traffic error: ${(err as Error).message}`);
            return [];
        }
    }

    async getChartData(token: string, period = '24h'): Promise<unknown[]> {
        try {
            const response = await firstValueFrom(
                this.httpService.get(`${this.backendUrl}/api/stats/traffic`, {
                    headers: { Authorization: `Bearer ${token}` },
                    params: { period },
                    timeout: this.requestTimeout,
                }).pipe(
                    timeout(this.requestTimeout),
                    catchError((err: Error) => {
                        this.logger.warn(`Failed to get chart data: ${err.message}`);
                        return of({ data: {} });
                    }),
                ),
            );
            const history: Record<string, unknown>[] = response.data?.history ?? [];
            return history.map(snap => ({
                ts: formatTs(snap.timestamp as string),
                rx: snap.bytes_rx ?? 0,
                tx: snap.bytes_tx ?? 0,
            }));
        } catch (err) {
            this.logger.error(`Chart data error: ${(err as Error).message}`);
            return [];
        }
    }
}

function formatTs(iso: string): string {
    if (!iso) return '';
    const d = new Date(iso);
    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
}
