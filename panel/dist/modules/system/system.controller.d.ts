import type { Response } from 'express';
import { SystemService } from './system.service';
export declare class SystemController {
    private readonly systemService;
    constructor(systemService: SystemService);
    getSystemInfo(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getStats(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    reloadConfig(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getHealth(res: Response): Promise<Response<any, Record<string, any>>>;
    getConfig(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    updateConfig(auth: string, body: any, res: Response): Promise<Response<any, Record<string, any>>>;
    getBackup(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    restoreBackup(auth: string, body: any, res: Response): Promise<Response<any, Record<string, any>>>;
    renewCert(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getProbeStats(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    probeBlock(auth: string, ip: string, reason: string, res: Response): Promise<Response<any, Record<string, any>>>;
    probeUnblock(auth: string, ip: string, res: Response): Promise<Response<any, Record<string, any>>>;
    getMLConfig(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    rotateMLToken(auth: string, res: Response): Promise<Response<any, Record<string, any>>>;
    generateQR(data: string, res: Response): Promise<Response<any, Record<string, any>>>;
}
