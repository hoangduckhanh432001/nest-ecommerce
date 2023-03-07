import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, Req } from '@nestjs/common';
// import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigService } from 'src/config/config.service';
import { Request as RequestType } from 'express';
import { request } from 'http';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      //   ignoreExpiration: false,
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number; email: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    return user;
  }
}

@Injectable()
export class JwtStrategyFromQueryString extends PassportStrategy(
  Strategy,
  'jwt-query',
) {
  constructor(config: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromUrlQueryParameter('token'),
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number; email: string; role: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    return user;
  }
}

@Injectable()
export class JwtStrategyFromCookie extends PassportStrategy(
  Strategy,
  'jwt-cookie',
) {
  constructor(config: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          let token = null;
          if (request && request.cookies) {
            token = request.cookies['accessToken'];
          }
          return token;
        },
      ]),
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number; email: string; role: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    return user;
  }
}

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(config: ConfigService, private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        RefreshTokenStrategy.extractJWT,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: config.get('REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(payload: { sub: number; email: string; role: string }) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: payload.sub,
      },
    });
    return payload;
  }
  private static extractJWT(req: RequestType): string | null {
    if (req.cookies && 'refresh_token' in req.cookies) {
      return req.cookies.refresh_token;
    }
    return null;
  }
}
