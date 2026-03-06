import { Controller, Get, Post, Put, Delete, Body, Param, Headers, Res, HttpStatus } from '@nestjs/common';
import type { Response } from 'express';
import { UsersService } from './users.service';

class CreateUserDto {
    email: string;
    password?: string;
    traffic_limit?: number;
    valid_until?: string;
    obfs_profile?: string;
    marionette_profile?: string;
    russian_service?: string;
}

@Controller()
export class UsersController {
    constructor(private readonly usersService: UsersService) { }

    @Get('api/users')
    async getUsers(@Headers('authorization') auth: string, @Res() res: Response) {
        try {
            const token = auth?.replace('Bearer ', '');
            const users = await this.usersService.getUsers(token);
            return res.json({ success: true, users });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.INTERNAL_SERVER_ERROR;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch users';
            return res.status(status).json({ success: false, error: msg });
        }
    }

    @Post('api/users')
    async createUser(
        @Headers('authorization') auth: string,
        @Body() dto: CreateUserDto,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.createUser(token, {
                username: dto.email,
                trafficLimit: dto.traffic_limit,
                expiryDate: dto.valid_until,
                obfsProfile: dto.obfs_profile,
                marionetteProfile: dto.marionette_profile,
                russianService: dto.russian_service,
            });
            return res.json({ success: true, user });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to create user';
            return res.status(status).json({ success: false, error: msg });
        }
    }

    @Put('api/users/:id')
    async updateUser(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Body() body: { email?: string; status?: string },
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const user = await this.usersService.updateUser(token, id, {
                username: body.email,
                status: body.status,
            });
            return res.json({ success: true, user });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to update user';
            return res.status(status).json({ success: false, error: msg });
        }
    }

    @Delete('api/users/:id')
    async deleteUser(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            await this.usersService.deleteUser(token, id);
            return res.json({ success: true });
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to delete user';
            return res.status(status).json({ success: false, error: msg });
        }
    }

    @Post('api/keys/connection')
    async generateConnectionKey(
        @Headers('authorization') auth: string,
        @Body() body: any,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const result = await this.usersService.generateConnectionKey(token, body);
            return res.json(result);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to generate key';
            return res.status(status).json({ success: false, error: msg });
        }
    }

    @Get('api/users/:id/stats')
    async getUserStats(
        @Headers('authorization') auth: string,
        @Param('id') id: string,
        @Res() res: Response,
    ) {
        try {
            const token = auth?.replace('Bearer ', '');
            const stats = await this.usersService.getUserStats(token, id);
            return res.json(stats);
        } catch (err: any) {
            const status = err?.response?.status || HttpStatus.BAD_REQUEST;
            const msg = err?.response?.data?.error || err?.response?.data?.message || err?.message || 'Failed to fetch stats';
            return res.status(status).json({ success: false, error: msg });
        }
    }
}
