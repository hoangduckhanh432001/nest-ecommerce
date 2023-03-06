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
  async signin(dto: AuthDto) {
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
    const token = await this.signToken(user.id, user.email, user.role);
    // TODO: set access token ở local storage
    // localStorage.setItem('accessToken', token.access_token);
    return [user, token];
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

      return { message: 'Signup successful!', token: token, user };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('Credentials already taken!');
      }
      throw error;
    }
  }

  // -------------------------------------------------------------------------------

  async confirmAccount(user: User) {
    console.log('mmmm', user.isActive);

    try {
      if (user) {
        if (!user.isActive) {
          const userEmail = user.email;
          await this.prisma.user.update({
            where: { email: userEmail },
            data: { isActive: true },
          });
        } else {
          return { message: 'The account is already confirmed!' };
        }
      }
    } catch (error) {
      throw new UnauthorizedException('Invalid JWT token!');
    }
    return { message: 'Account is confirmed!' };
  }

  // ------------------------------------------------------------------------------
  async signToken(
    userId: number,
    email: string,
    role: string,
  ): Promise<Promise<AuthTokenDto>> {
    const payload = { sub: userId, email, role };
    const tokens = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get('JWT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get('REFRESH_SECRET'),
        expiresIn: '7d',
      }),
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
}
