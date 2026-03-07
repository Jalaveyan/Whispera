import { Controller, Get, Post, Body, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { OutboundsService, Outbound } from './outbounds.service';

@Controller()
export class OutboundsController {
    constructor(private readonly outboundsService: OutboundsService) { }

    @Get('api/outbounds')
    async getOutbounds(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const outbounds = await this.outboundsService.getOutbounds(token);
            return res.json({ success: true, outbounds });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch outbounds' });
        }
    }

    @Post('api/outbounds')
    async addOutbound(
        @Headers('authorization') auth: string,
        @Body() outbound: Partial<Outbound>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.outboundsService.addOutbound(token, outbound);
            return res.json({ success: true, outbound: result });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add outbound' });
        }
    }

    @Post('api/outbounds/delete')
    async deleteOutbound(
        @Headers('authorization') auth: string,
        @Body('tag') tag: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.outboundsService.deleteOutbound(token, tag);
            return res.json({ success: true });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete outbound' });
        }
    }
}
