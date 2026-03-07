import { Controller, Get, Post, Delete, Body, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { InboundsService, Inbound } from './inbounds.service';

@Controller()
export class InboundsController {
    constructor(private readonly inboundsService: InboundsService) { }

    @Get('api/inbounds')
    async getInbounds(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const inbounds = await this.inboundsService.getInbounds(token);
            return res.json({ success: true, inbounds });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch inbounds' });
        }
    }

    @Post('api/inbounds')
    async addInbound(
        @Headers('authorization') auth: string,
        @Body() inbound: Partial<Inbound>,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.inboundsService.addInbound(token, inbound);
            return res.json({ success: true, inbound: result });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to add inbound' });
        }
    }

    @Delete('api/inbounds/:tag')
    async deleteInbound(
        @Headers('authorization') auth: string,
        @Param('tag') tag: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.inboundsService.deleteInbound(token, tag);
            return res.json({ success: true });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to delete inbound' });
        }
    }

    @Get('api/publickey/:port')
    async getPublicKey(
        @Headers('authorization') auth: string,
        @Param('port') port: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const publicKey = await this.inboundsService.getPublicKey(token, parseInt(port));
            return res.json({ success: true, public_key: publicKey });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to get public key' });
        }
    }
}
