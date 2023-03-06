import { Injectable } from '@nestjs/common';
import {
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common/exceptions';
import { ExecutionContext } from '@nestjs/common/interfaces';
import { AuthGuard } from '@nestjs/passport';
import { ExtractJwt } from 'passport-jwt';
import { JwtBlacklistService } from '../auth.service';

@Injectable()
export class JwtGuardFromQueryString extends AuthGuard('jwt-query') {
  constructor(private jwtBlacklistService: JwtBlacklistService) {
    super();
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = ExtractJwt.fromUrlQueryParameter('token')(request);
    if (!token) {
      throw new BadRequestException('Token is invalid!');
    }
    const isBlacklisted = await this.jwtBlacklistService.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token is in blacklist!');
    }
    return super.canActivate(context) as boolean;
  }
}
@Injectable()
export class JwtGuardFromHeader extends AuthGuard('jwt') {
  constructor(private jwtBlacklistService: JwtBlacklistService) {
    super();
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(request);
    if (!token) {
      throw new BadRequestException('Token is invalid!');
    }
    const isBlacklisted = await this.jwtBlacklistService.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token is in blacklist!');
    }
    return super.canActivate(context) as boolean;
  }
}
