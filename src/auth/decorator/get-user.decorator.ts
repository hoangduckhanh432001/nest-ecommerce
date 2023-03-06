import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetUser = createParamDecorator(
  (data: string | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    console.log('data', data);

    if (data) {
      console.log('data', request.user[data], typeof request.user[data]);
      return request.user[data];
    }

    return request.user;
  },
);
