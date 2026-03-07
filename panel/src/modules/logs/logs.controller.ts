import { Controller, Get, Query, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { LogsService } from './logs.service';

@Controller()
export class LogsController {
    constructor(private readonly logsService: LogsService) { }

    @Get('api/logs')
    async getLogs(
        @Headers('authorization') auth: string,
        @Query('limit') limit: number,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const logs = await this.logsService.getLogs(token, limit);
            return res.json({ success: true, logs });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            return res.status(status).json({ success: false, error: err?.response?.data?.error || err?.message || 'Failed to fetch logs' });
        }
    }
}
