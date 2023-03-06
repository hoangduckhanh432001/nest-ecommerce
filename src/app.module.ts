import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { PrismaModule } from './prisma/prisma.module';
// import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { join } from 'path';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { ProductsModule } from './products/products.module';
import { ConfigModule } from './config/config.module';
import { ConfigService } from 'src/config/config.service';

const configFolder = { folder: './config' };
const configObject = new ConfigService(configFolder);

@Module({
  imports: [
    AuthModule,
    UserModule,
    BookmarkModule,
    PrismaModule,

    // ConfigModule.forRoot({ isGlobal: true }),
    ConfigModule.register(configFolder),

    MailerModule.forRoot({
      transport: {
        // host: process.env.HOST_MAIL_SERVER,
        host: configObject.get('HOST_MAIL_SERVER'),
        port: 587,
        secure: false,
        auth: {
          user: configObject.get('EMAIL_SERVER'),
          pass: configObject.get('PASSWORD'),
        },
      },
      preview: true,
      defaults: {
        from: '"No Reply" <chris@example.com>',
      },
      template: {
        dir: join(__dirname, '/mail/template/'),
        adapter: new HandlebarsAdapter(),
        options: {
          strict: true,
        },
      },
    }),

    ProductsModule,
  ],
})
export class AppModule {}
