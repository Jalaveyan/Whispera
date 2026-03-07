import { Controller, Get, Post, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { SessionsService } from './sessions.service';

@Controller()
export class SessionsController {
    constructor(private readonly sessionsService: SessionsService) { }

    @Get('api/sessions')
    async getSessions(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const sessions = await this.sessionsService.getSessions(token);
            return res.json({ success: true, sessions });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch sessions' });
        }
    }

    @Post('api/sessions/:id/kill')
    async killSession(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.sessionsService.killSession(token, id);
            return res.json({ success: true });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to kill session' });
        }
    }
}
