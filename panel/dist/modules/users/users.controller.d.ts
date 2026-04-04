import type { Response } from 'express';
import { UsersService } from './users.service';
declare class CreateUserDto {
    email: string;
    password?: string;
    traffic_limit?: number;
    valid_until?: string;
    obfs_profile?: string;
    marionette_profile?: string;
    russian_service?: string;
}
export declare class UsersController {
    private readonly usersService;
    constructor(usersService: UsersService);
    getUsers(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    createUser(auth: string, dto: CreateUserDto, res: Response): Promise<Response<any, Record<string, any>>>;
    updateUser(auth: string, id: string, body: {
        username?: string;
        email?: string;
        status?: string;
        trafficLimit?: number;
        expiryDate?: string;
        obfsProfile?: string;
        russianService?: string;
        marionetteProfile?: string;
    }, res: Response): Promise<Response<any, Record<string, any>>>;
    deleteUser(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
    generateConnectionKey(auth: string, body: any, res: Response): Promise<Response<any, Record<string, any>>>;
    getUserStats(auth: string, id: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
export {};
