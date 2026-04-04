import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
export interface Subscription {
    id: string;
    name: string;
    token: string;
    sub_url: string;
    user_ids: number[];
    transports: string[];
    created_at: string;
    updated_at: string;
}
export interface CreateSubscriptionDto {
    name: string;
    user_ids?: number[];
    transports?: string[];
}
export declare class SubscriptionsService {
    private readonly httpService;
    private readonly configService;
    private readonly backendUrl;
    constructor(httpService: HttpService, configService: ConfigService);
    getSubscriptions(token: string, host?: string, proto?: string): Promise<Subscription[]>;
    addSubscription(token: string, dto: CreateSubscriptionDto, host?: string, proto?: string): Promise<Subscription>;
    updateSubscription(token: string, id: string, dto: Partial<CreateSubscriptionDto>): Promise<Subscription>;
    deleteSubscription(token: string, id: string): Promise<void>;
    getSubscriptionContent(token: string): Promise<string>;
}
