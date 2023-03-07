import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
// import { PrismaModule } from 'src/prisma/prisma.module';
import { AuthController } from './auth.controller';
import { AuthService, JwtBlacklistService } from './auth.service';
import { RolesGuard } from './guard/role.guard';
import {
  JwtStrategy,
  JwtStrategyFromCookie,
  JwtStrategyFromQueryString,
  RefreshTokenStrategy,
} from './strategy';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    JwtBlacklistService,
    JwtStrategyFromQueryString,
    RolesGuard,
    RefreshTokenStrategy,
    JwtStrategyFromCookie,
  ],
  imports: [JwtModule.register({})],
  exports: [JwtBlacklistService],
})
export class AuthModule {}
