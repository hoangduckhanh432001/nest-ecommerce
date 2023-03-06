import { DefaultValuePipe } from '@nestjs/common';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';
import { IsStrongPassword } from '../validator';

export class AuthDto {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @IsNotEmpty()
  @IsString()
  password: string;
}

export class AuthDtoSignup {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;

  @MinLength(8)
  @Matches(/^(?=.*[a-z])/, {
    message: 'Password need contain at least 1 lowercase character',
  })
  @Matches(/^(?=.*[A-Z])/, {
    message: 'Password need contain at least 1 uppercase character',
  })
  @IsNotEmpty()
  @IsString()
  password: string;

  @IsNotEmpty()
  @IsString()
  confirmPassword: string;
}

export class AuthDtoChangePassword {
  @IsNotEmpty()
  @IsString()
  oldPassword: string;

  @MinLength(8)
  @Matches(/^(?=.*[a-z])/, {
    message: 'Password need contain at least 1 lowercase character',
  })
  @Matches(/^(?=.*[A-Z])/, {
    message: 'Password need contain at least 1 uppercase character',
  })
  @IsNotEmpty()
  @IsString()
  newPassword: string;

  @IsNotEmpty()
  @IsString()
  confirmNewPassword: string;
}

export class AuthDtoResetPasswordConfirm {
  @MinLength(8)
  @Matches(/^(?=.*[a-z])/, {
    message: 'Password need contain at least 1 lowercase character',
  })
  @Matches(/^(?=.*[A-Z])/, {
    message: 'Password need contain at least 1 uppercase character',
  })
  @IsNotEmpty()
  @IsString()
  newPassword: string;

  @IsNotEmpty()
  @IsString()
  confirmNewPassword: string;
}

export class AuthDtoResetPassword {
  @IsEmail()
  @IsNotEmpty()
  @IsString()
  email: string;
}

export class AuthTokenDto {
  accessToken: string;
  refreshToken: string;
}
