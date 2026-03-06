import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

export interface Inbound {
    tag: string;
    protocol: string;
    listen: string;
    port: number;
    ports?: number[];   // multiport
    transport: string;
    security: string;
    private_key?: string;
    public_key?: string;
}

export interface TransportCredentials {
    transport: string;
    credentials: Record<string, unknown>;
    client_config: Record<string, unknown>;
}

@Injectable()
export class InboundsService {
    private readonly backendUrl: string;

    constructor(
        private readonly httpService: HttpService,
        private readonly configService: ConfigService,
    ) {
        this.backendUrl = this.configService.get('BACKEND_URL') || 'http://localhost:8080';
    }

    async getInbounds(token: string): Promise<Inbound[]> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/inbounds`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.inbounds || response.data || [];
    }

    async addInbound(token: string, inbound: Partial<Inbound>): Promise<Inbound> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/inbounds/add`,
                inbound,
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data;
    }

    async deleteInbound(token: string, tag: string): Promise<void> {
        await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/inbounds/delete`,
                { tag },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
    }

    async getPublicKey(token: string, port: number): Promise<string> {
        const response = await firstValueFrom(
            this.httpService.get(`${this.backendUrl}/api/inbounds/pubkey?port=${port}`, {
                headers: { Authorization: `Bearer ${token}` },
            }),
        );
        return response.data.public_key || response.data;
    }

    async generateTransportCredentials(token: string, transport: string): Promise<TransportCredentials> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/keys/transport`,
                { transport },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.result;
    }

    async generateMultiTransportCredentials(
        token: string,
        transports: string[],
    ): Promise<Record<string, TransportCredentials>> {
        const response = await firstValueFrom(
            this.httpService.post(
                `${this.backendUrl}/api/keys/multi-transport`,
                { transports },
                { headers: { Authorization: `Bearer ${token}` } },
            ),
        );
        return response.data.results;
    }
}
