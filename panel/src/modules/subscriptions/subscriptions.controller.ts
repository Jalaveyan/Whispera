import { Controller, Get, Post, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { SubscriptionsService } from './subscriptions.service';
import type { CreateSubscriptionDto } from './subscriptions.service';

@Controller()
export class SubscriptionsController {
    constructor(private readonly subscriptionsService: SubscriptionsService) { }

    @Get('api/subscriptions')
    async getSubscriptions(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const subscriptions = await this.subscriptionsService.getSubscriptions(token);
            return res.json({ success: true, subscriptions });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch subscriptions';
            return res.status(err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/add')
    async addSubscription(
        @Headers('authorization') auth: string,
        @Body() dto: CreateSubscriptionDto,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.subscriptionsService.addSubscription(token, dto);
            return res.json({ success: true, subscription: result });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to add subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/update')
    async updateSubscription(
        @Headers('authorization') auth: string,
        @Body() body: { id: string } & Partial<CreateSubscriptionDto>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const { id, ...dto } = body;
            const result = await this.subscriptionsService.updateSubscription(token, id, dto);
            return res.json({ success: true, subscription: result });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/delete')
    async deleteSubscription(
        @Headers('authorization') auth: string,
        @Body('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.subscriptionsService.deleteSubscription(token, id);
            return res.json({ success: true });
        } catch (err: any) {
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete subscription';
            return res.status(err?.response?.status || HttpStatus.BAD_REQUEST).json({ success: false, error: msg });
        }
    }

    @Post('api/subscriptions/update-all')
    async updateAll(@Headers('authorization') auth: string, @Res() res: Response) {
        // No-op: subscriptions are served live, no polling needed
        void auth;
        return res.json({ success: true });
    }
}
