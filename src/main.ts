import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { envs } from './config/envs';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';

async function bootstrap() {

  const logger = new Logger('Auth MS')

  const app = await NestFactory.createMicroservice<MicroserviceOptions>(AppModule, {
    transport : Transport.NATS,
    options : { servers : envs.nats_servers }
  });

  app.useGlobalPipes(new ValidationPipe({
    whitelist : true,
    forbidNonWhitelisted : true
  }))

  await app.listen();

  logger.log(`Auth MS running on ${envs.port}`)

}
bootstrap();
