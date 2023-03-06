import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { JwtBlacklistService } from '../auth.service';

// TODO: Auth guard already implement check blacklisted token...
@Injectable()
export class BlacklistInterceptor implements NestInterceptor {
  constructor(private readonly blacklistService: JwtBlacklistService) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization.split(' ')[1];
    const isBlacklisted = await this.blacklistService.isBlacklisted(token);

    if (isBlacklisted) {
      throw new HttpException(
        'Token is in blacklisted!',
        HttpStatus.UNAUTHORIZED,
      );
    }
    return next.handle();
  }
}
