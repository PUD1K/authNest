import { Module } from '@nestjs/common';
import { RolesService } from './roles.service';
import { RolesController } from './roles.controller';
import { SequelizeModule } from '@nestjs/sequelize';
import { UserRoles } from './user-roles.model';
import { User } from 'src/users/users.model';
import { Role } from './roles.model';
import { UsersModule } from 'src/users/users.module';

@Module({
  providers: [RolesService],
  controllers: [RolesController],
  imports: [
    SequelizeModule.forFeature([Role, User, UserRoles]),
  ],
  exports:[
    RolesService
  ]
})
export class RolesModule {}
