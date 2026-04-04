import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface User {
    id: number;
    username: string;
    privateKey?: string;
    publicKey?: string;
    upload: number;
    download: number;
    trafficLimit: number;
    expiryDate?: string;
    status: string;
    createdAt: string;
    obfsProfile?: string;
    marionetteProfile?: string;
    russianService?: string;
}
export interface CreateUserDto {
    username: string;
    trafficLimit?: number;
    expiryDate?: string;
    obfsProfile?: string;
    marionetteProfile?: string;
    russianService?: string;
}
export declare class UsersService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getUsers(token: string): Promise<User[]>;
    createUser(token: string, dto: CreateUserDto): Promise<User>;
    updateUser(token: string, id: string, data: Partial<CreateUserDto> & {
        status?: string;
    }): Promise<User>;
    deleteUser(token: string, id: string): Promise<void>;
    generateConnectionKey(token: string, opts: {
        psk?: string;
        name?: string;
        transport?: string;
        sni?: string;
        phantom?: boolean;
        asn?: boolean;
        tls?: string;
        russianService?: string;
        port?: number;
        transportConfig?: Record<string, unknown>;
    }): Promise<any>;
    getUserStats(token: string, id: string): Promise<any>;
}
