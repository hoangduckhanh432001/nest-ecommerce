import {
  Controller,
  Post,
  Body,
  UseGuards,
  Headers,
  Get,
  Req,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { AuthService } from './auth.service';
import { GetUser } from './decorator';
import {
  AuthDto,
  AuthDtoChangePassword,
  AuthDtoResetPassword,
  AuthDtoResetPasswordConfirm,
  AuthDtoSignup,
} from './dto';
import {
  JwtGuardFromCookie,
  JwtGuardFromHeader,
  JwtGuardFromQueryString,
} from './guard';
import { RolesGuard } from './guard/role.guard';
import { Roles } from './auth.role';
import { Res } from '@nestjs/common/decorators';
import { Response, Request as RequestType } from 'express';

@Roles(['user'])
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: AuthDtoSignup) {
    console.log('signup');
    return this.authService.signup(dto);
  }

  @Post('signin')
  signin(@Body() dto: AuthDto, @Res() res: Response) {
    console.log('signin');
    return this.authService.signin(dto, res);
  }

  @Post('signout')
  async signout(@Headers() headers) {
    console.log('sign out');
    const authToken = headers.authorization;
    const token = authToken.split(' ')[1];
    return await this.authService.signout(token);
  }

  @Get('confirm_account')
  // @UseGuards(JwtGuardFromHeader)
  @UseGuards(JwtGuardFromCookie, RolesGuard)
  confirm(
    @GetUser() user: User,
    @Res() res: Response,
    @Req() req: RequestType,
  ) {
    return this.authService.confirmAccount(user, res);
  }

  @Post('change_password')
  @UseGuards(JwtGuardFromHeader)
  changePassword(@GetUser() user: User, @Body() dto: AuthDtoChangePassword) {
    return this.authService.changePassword(user, dto);
  }

  @Post('reset_password')
  resetPassword(@Body() dto: AuthDtoResetPassword) {
    return this.authService.resetPassword(dto);
  }

  @Post('reset_password_confirm')
  @UseGuards(JwtGuardFromQueryString)
  resetPasswordConfirm(
    @Body() dto: AuthDtoResetPasswordConfirm,
    @GetUser() user: User,
  ) {
    return this.authService.resetPasswordConfirm(user, dto);
  }
}
