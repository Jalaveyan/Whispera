import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface RoutingRule {
    id: string;
    type: string;
    condition: string;
    outbound: string;
    priority: number;
    enabled: boolean;
}
export declare class RoutingService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getRules(token: string): Promise<RoutingRule[]>;
    addRule(token: string, rule: Partial<RoutingRule>): Promise<RoutingRule>;
    deleteRule(token: string, id: string): Promise<void>;
}
