import {
  Body,
  Controller,
  Get,
  Patch,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { User } from '@prisma/client';
import { Roles } from 'src/auth/auth.role';
import { BlacklistInterceptor } from 'src/auth/decorator/check-jwt-blackist.decorator';
import { GetUser } from '../auth/decorator';
import { JwtGuardFromHeader, JwtGuardFromQueryString } from '../auth/guard';
import { EditUserDto } from './dto';
import { UserService } from './user.service';

@Roles(['user'])
@UseGuards(JwtGuardFromHeader)
@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  // ----------------------------------------
  @Get('me')
  getMe(@GetUser() user: User) {
    return user;
  }

  // -----------------------------------------------
  @Patch('me/update')
  editUser(@GetUser('sub') userId: number, @Body() dto: EditUserDto) {
    console.log('userId', userId);
    return this.userService.editUser(userId, dto);
  }

  @Roles(['admin'])
  @Get('all')
  getAll() {
    return this.userService.getAllUser();
  }

  @Roles(['admin'])
  @Get(':id')
  getSingleUser() {}
}
