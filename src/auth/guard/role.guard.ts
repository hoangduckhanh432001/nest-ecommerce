import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }
    console.log('ở bên role guard', context.switchToHttp().getRequest().user);

    const { role } = context.switchToHttp().getRequest().user;
    if (role === 'user') {
      requiredRoles.push('admin');
    }
    return requiredRoles.includes(role);
  }
}
