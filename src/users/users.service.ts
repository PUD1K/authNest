import { Injectable, HttpStatus, HttpException } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { RolesService } from 'src/roles/roles.service';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AddRoleDto } from './dto/add-role.dto';
import { User } from './users.model';

@Injectable()
export class UsersService {

    constructor(@InjectModel(User) private userRepository: typeof User,
                private roleService: RolesService) {}

    async createUser(dto: CreateUserDto){
        const user = await this.userRepository.create(dto);
        // const role = await this.roleService.getRoleByValue("ADMIN");
        // await user.$set('roles', [role.id]);
        // user.roles = [role];
        return user;
    }

    async getAllUsers(){
        const users = await this.userRepository.findAll({include: {all: true}});
        return users;
    }

    async getUserByEmail(email: string){
        const user = await this.userRepository.findOne({where: {email}, include: {all: true}});
        return user;
    }

    async addRole(dto: AddRoleDto){
        console.log(dto);
        const user = await this.userRepository.findByPk(dto.userId);
        const role = await this.roleService.getRoleByValue(dto.value);
        const roleExist = await user.$has('roles1', [role.id]);
        console.log(roleExist);
        if(user && role){
            await user.$add('roles', role.id);
            return dto;
        }
        throw new HttpException('Пользователь не найден', HttpStatus.FORBIDDEN);
    }
}
