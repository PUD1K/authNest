import {Module} from '@nestjs/common'
import { ConfigModule } from '@nestjs/config';
import {SequelizeModule} from '@nestjs/sequelize';
import { UsersModule } from './users/users.module';
import { RolesController } from './roles/roles.controller';
import { RolesModule } from './roles/roles.module';
import { AuthModule } from './auth/auth.module';
import { User } from './users/users.model';
import { Role } from './roles/roles.model';
import { UserRoles } from './roles/user-roles.model';
import { ServeStaticModule } from '@nestjs/serve-static';
import * as path from 'path';

@Module({
    imports:[
        ConfigModule.forRoot({
            envFilePath: `.${process.env.NODE_ENV}.env`
        }),
        ServeStaticModule.forRoot({
            rootPath: path.resolve(__dirname, '..', 'static'),
        }),
        SequelizeModule.forRoot({
            dialect: 'postgres',
            host: process.env.POSTGRES_HOST,
            port: Number(process.env.POSTGRES_PORT),
            username: process.env.POSTGRES_USER,
            password: process.env.POSTGRES_PASSWORD,
            database: process.env.POSTGRES_DB,
            models: [User, UserRoles, Role],
            autoLoadModels: true
          }),
        UsersModule,
        RolesModule,
        AuthModule,
    ],
    controllers: [RolesController]
})
export class AppModule {}