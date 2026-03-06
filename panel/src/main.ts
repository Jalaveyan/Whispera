import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { join } from 'path';
import { readFileSync, existsSync } from 'fs';
import * as http from 'http';
import * as express from 'express';

async function bootstrap() {
  const tlsCertPath = process.env.TLS_CERT;
  const tlsKeyPath = process.env.TLS_KEY;

  let httpsOptions: { cert: Buffer; key: Buffer } | undefined;
  if (tlsCertPath && tlsKeyPath && existsSync(tlsCertPath) && existsSync(tlsKeyPath)) {
    httpsOptions = {
      cert: readFileSync(tlsCertPath),
      key: readFileSync(tlsKeyPath),
    };
  }

  const app = await NestFactory.create(AppModule, httpsOptions ? { httpsOptions } : {});

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );

  app.enableCors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
  });

  const publicPath = join(__dirname, '..', 'public');
  app.use(express.static(publicPath));

  const httpAdapter = app.getHttpAdapter();
  httpAdapter.get('*', (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.url.startsWith('/api/')) {
      return next();
    }
    res.sendFile(join(publicPath, 'index.html'));
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  const proto = httpsOptions ? 'https' : 'http';
  console.log(`Whispera Panel running on ${proto}://localhost:${port}`);

  // If running HTTPS, start an HTTP redirect server on HTTP_PORT (default 80)
  if (httpsOptions) {
    const httpPort = parseInt(process.env.HTTP_PORT || '80', 10);
    const httpsPort = String(port);
    http.createServer((req, res) => {
      const host = (req.headers.host || '').replace(/:\d+$/, '');
      res.writeHead(301, { Location: `https://${host}:${httpsPort}${req.url}` });
      res.end();
    }).listen(httpPort, () => {
      console.log(`HTTP→HTTPS redirect on port ${httpPort}`);
    });
  }
}
bootstrap();
