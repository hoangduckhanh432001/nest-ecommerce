import { Injectable } from '@nestjs/common';
// import { ConfigService } from '@nestjs/config/dist';
import { PrismaClient } from '@prisma/client';
import { ConfigService } from 'src/config/config.service';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(config: ConfigService) {
    super({
      datasources: {
        db: {
          url: config.get('DATABASE_URL'),
        },
      },
    });
  }
}
