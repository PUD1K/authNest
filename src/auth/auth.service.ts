import { HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt/dist';
import { HttpStatus } from '@nestjs/common/enums';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { User } from 'src/users/users.model';
import * as bcrypt from 'bcryptjs'
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {

    constructor(private userService: UsersService, 
                private jwtService: JwtService) {}

    async login(userDto: CreateUserDto) {
        const user = await this.validateUser(userDto);
        return this.generateToken(user);
    }

    async registration(userDto: CreateUserDto) {
        const candidate = await this.userService.getUserByEmail(userDto.email);
        if (candidate){
            throw new HttpException('Пользователь с таким email уже существует', HttpStatus.BAD_REQUEST);
        }
        const hashPassword = await bcrypt.hash(userDto.password, 5)
        const user = await this.userService.createUser({...userDto, password: hashPassword});

        return {
            email: user.email,
            password: user.password,
            token: await (await this.generateToken(user)).token
        };

        // return this.generateToken(user);
    }

    private async generateToken(user: User){
        const payload = {email: user.email, id: user.id, roles: user.roles};
        // помещаем всю инфу о пользователе в тело токена
        return {
            token: this.jwtService.sign(payload),
        }
    }

    private async validateUser(userDto: CreateUserDto){
        const user = await this.userService.getUserByEmail(userDto.email);
        const password_equals = await bcrypt.compare(userDto.password, user.password);
        if(user && password_equals){
            return user;
        }
        throw new UnauthorizedException({message: 'Неверное имя пользователя или пароль'});
    }
}
