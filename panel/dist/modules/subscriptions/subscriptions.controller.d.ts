import type { Request } from 'express';
import type { Response } from 'express';
import { SubscriptionsService } from './subscriptions.service';
import type { CreateSubscriptionDto } from './subscriptions.service';
export declare class SubscriptionsController {
    private readonly subscriptionsService;
    constructor(subscriptionsService: SubscriptionsService);
    getSubscriptions(auth: string, req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
    addSubscription(auth: string, dto: CreateSubscriptionDto, req: Request, res: Response): Promise<Response<any, Record<string, any>>>;
    updateSubscription(auth: string, body: {
        id: string;
    } & Partial<CreateSubscriptionDto>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteSubscription(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    updateAll(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    serveSubscription(token: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
