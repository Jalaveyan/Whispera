import type { Response } from 'express';
import { RoutingService, RoutingRule } from './routing.service';
export declare class RoutingController {
    private readonly routingService;
    constructor(routingService: RoutingService);
    getRules(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    addRule(auth: string, rule: Partial<RoutingRule>, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteRule(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
