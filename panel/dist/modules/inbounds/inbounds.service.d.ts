import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Inbound {
    tag: string;
    protocol: string;
    listen: string;
    port: number;
    ports?: number[];
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
export declare class InboundsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getInbounds(token: string): Promise<Inbound[]>;
    addInbound(token: string, inbound: Partial<Inbound>): Promise<Inbound>;
    deleteInbound(token: string, tag: string): Promise<void>;
    getPublicKey(token: string, port: number): Promise<string>;
    generateTransportCredentials(token: string, transport: string): Promise<TransportCredentials>;
    generateMultiTransportCredentials(token: string, transports: string[]): Promise<Record<string, TransportCredentials>>;
}
