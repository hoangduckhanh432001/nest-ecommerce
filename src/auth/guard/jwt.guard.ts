import { Injectable } from '@nestjs/common';
import {
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common/exceptions';
import { ExecutionContext } from '@nestjs/common/interfaces';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { ExtractJwt } from 'passport-jwt';
import { AuthService, JwtBlacklistService } from '../auth.service';

@Injectable()
export class JwtGuardFromQueryString extends AuthGuard('jwt-query') {
  constructor(
    private jwtBlacklistService: JwtBlacklistService,
    private authService: AuthService,
    private jwtService: JwtService,
  ) {
    super();
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const token =
      request.cookies['accessToken'] ||
      ExtractJwt.fromAuthHeaderAsBearerToken()(request) ||
      ExtractJwt.fromUrlQueryParameter('token')(request);

    console.log('-----start-get-route----', token);

    if (!token) {
      throw new BadRequestException('Token is missing!');
    }
    const isBlacklisted = await this.jwtBlacklistService.isBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token is in blacklist!');
    }

    const isAccessTokenValid = this.authService.verifyAccessToken(token);
    if (!isAccessTokenValid) {
      console.log('token hết hạn rồi');
      const tokenFromQueryString =
        ExtractJwt.fromUrlQueryParameter('token')(request);
      // if (tokenFromQueryString) {
      // }

      const refreshToken = request.cookies['refreshToken'];
      if (!refreshToken) {
        throw new UnauthorizedException(
          'Access token is invalid and no refresh token found!',
        );
      }
      const { userId, email, role } = this.jwtService.decode(refreshToken) as {
        userId: number;
        email: string;
        role: string;
      };
      const isBlacklisted = await this.jwtBlacklistService.isBlacklisted(
        refreshToken,
      );
      if (isBlacklisted) {
        throw new UnauthorizedException('Refresh token is in blacklist!');
      }
      const accessToken = await this.authService.generateAccessToken(
        userId,
        email,
        role,
      );
      console.log('trả access token về cho user');
      console.log('accessToken111', accessToken);

      // request.headers['authorization'] = `Bearer ${accessToken}`;
      response.cookie('accessToken', accessToken, { httpOnly: true });
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
