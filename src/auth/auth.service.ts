import { Injectable } from '@nestjs/common/decorators';
import { PrismaService } from 'src/prisma/prisma.service';
import {
  AuthDto,
  AuthDtoChangePassword,
  AuthDtoResetPassword,
  AuthDtoResetPasswordConfirm,
  AuthDtoSignup,
  AuthTokenDto,
} from './dto';
import * as argon from 'argon2';
import {
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
// import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import { Role, User } from '@prisma/client';
import { ConfigService } from 'src/config/config.service';
import { Response } from 'express';

@Injectable()
export class JwtBlacklistService {
  constructor(private prisma: PrismaService) {}

  async addToBlacklist(token: string): Promise<{ message: string }> {
    const new1 = await this.prisma.blacklistedToken.create({
      data: { token },
    });
    console.log(new1);
    return { message: 'Token added to blacklisted!' };
  }

  async isBlacklisted(token: string): Promise<boolean> {
    const blacklistedToken = await this.prisma.blacklistedToken.findUnique({
      where: { token },
    });

    return !!blacklistedToken;
  }
}

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
    private jwtBlacklistService: JwtBlacklistService,
    private mailService: MailerService,
  ) {}

  // ----------------------------------------------------------------------------------------
  async signin(dto: AuthDto, res: Response) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) throw new ForbiddenException('Credentials incorrect!');
    const matchPass = await argon.verify(user.hash, dto.password);
    if (!matchPass) throw new ForbiddenException('Credentials incorrect!');
    if (!user || !user.isActive) {
      throw new UnauthorizedException(
        'User is not active yet or invalid credentials!',
      );
    }
    const { accessToken, refreshToken } = await this.signToken(
      user.id,
      user.email,
      user.role,
    );
    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, { httpOnly: true });
    console.log('cookie:', res.cookie);

    // TODO: set access token in local storage
    return res.send([user, accessToken]);
  }

  // -------------------------------------------------------------------------------------
  async signup(dto: AuthDtoSignup) {
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Passwords do not match!');
    }
    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
          name: 'Chris Eagle',
        },
      });
      const token = (await this.signToken(user.id, user.email, user.role))
        .accessToken;
      // ---
      this.mailService.sendMail({
        to: dto.email,
        from: this.config.get('EMAIL_SERVER'),
        subject: 'Signup successful, verify email!',
        template: './email-signup',
        context: {
          user: user.name,
          url: `${this.config.get(
            'DOMAIN_NAME',
          )}auth/confirm_account?token=${token}`,
        },
      });

      return { message: 'Signup successful!', access_token: token, user };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('Credentials already taken!');
      }
      throw error;
    }
  }

  // -------------------------------------------------------------------------------

  async confirmAccount(user: User, res: Response) {
    try {
      if (user) {
        if (!user.isActive) {
          const userEmail = user.email;
          await this.prisma.user.update({
            where: { email: userEmail },
            data: { isActive: true },
          });
        } else {
          return res.send({ message: 'The account is already confirmed!' });
        }
      }
    } catch (error) {
      throw new UnauthorizedException('Invalid JWT token!');
    }
    // Thêm
    const { accessToken, refreshToken } = await this.signToken(
      user.id,
      user.email,
      user.role,
    );
    res.cookie('refreshToken', refreshToken, { httpOnly: true });
    res.cookie('accessToken', accessToken, { httpOnly: true });
    // Thêm
    console.log('cookie:', res.cookie);
    return res.send({ message: 'Account is confirmed!' });
  }

  // ------------------------------------------------------------------------------
  async signToken(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };
    // const tokens = await Promise.all([
    //   this.jwt.signAsync(payload, {
    //     secret: this.config.get('JWT_SECRET'),
    //     expiresIn: '1m',
    //   }),
    //   this.jwt.signAsync(payload, {
    //     secret: this.config.get('REFRESH_SECRET'),
    //     expiresIn: '7 days',
    //   }),
    // ]);
    const tokens = await Promise.all([
      this.generateAccessToken(userId, email, role),
      this.generateRefreshToken(userId, email, role),
    ]);

    return {
      accessToken: tokens[0],
      refreshToken: tokens[1],
    };
  }

  // -------------------------------------------------------------------------------------
  async signout(token: string) {
    // Add the token to the blacklist
    const isExist = await this.prisma.blacklistedToken.findUnique({
      where: { token },
    });
    if (!isExist) {
      return await this.jwtBlacklistService.addToBlacklist(token);
    }
    return { message: 'Log out' };
  }

  async changePassword(user: User, dto: AuthDtoChangePassword) {
    const matchPass = await argon.verify(user.hash, dto.oldPassword);
    if (!matchPass) throw new ForbiddenException('Old password incorrect!');

    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Passwords do not match. Try again!');
    }

    const newHash = await argon.hash(dto.newPassword);
    await this.prisma.user.update({
      where: { email: user.email },
      data: { hash: newHash },
    });
    console.log('12121212', user);

    return user;
  }

  async resetPassword(dto: AuthDtoResetPassword) {
    const email = dto.email;
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      throw new BadRequestException('Cannot find this email in system!');
    }
    const token = await (
      await this.signToken(user.id, user.email, user.role)
    ).accessToken;

    this.mailService.sendMail({
      to: dto.email,
      from: this.config.get('EMAIL_SERVER'),
      subject: 'Reset your password',
      template: './email-resetpass',
      context: {
        user: user.name,
        url: `${this.config.get(
          'DOMAIN_NAME',
        )}auth/reset_password_confirm?token=${token}`,
      },
    });
    return { message: 'Use this token to reset your password!', token };
  }

  async resetPasswordConfirm(user: User, dto: AuthDtoResetPasswordConfirm) {
    if (dto.newPassword !== dto.confirmNewPassword) {
      throw new BadRequestException('Passwords do not match. Try again!');
    }
    const newHash = await argon.hash(dto.newPassword);
    await this.prisma.user.update({
      where: { email: user.email },
      data: { hash: newHash },
    });
    return user;
  }

  generateAccessToken(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };
    const token = this.jwt.signAsync(payload, {
      secret: this.config.get('JWT_SECRET'),
      expiresIn: '30s',
    });
    return token;
  }

  generateRefreshToken(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };
    const token = this.jwt.signAsync(payload, {
      secret: this.config.get('REFRESH_SECRET'),
      expiresIn: '7d',
    });
    return token;
  }

  verifyAccessToken(token: string): boolean {
    try {
      this.jwt.verify(token, { secret: this.config.get('JWT_SECRET') });
      return true;
    } catch {
      return false;
    }
  }

  storeTokenInCookie(res: Response, authToken: AuthTokenDto) {
    res.cookie('refresh_token', authToken.refreshToken, {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      httpOnly: true,
    });
  }
}
