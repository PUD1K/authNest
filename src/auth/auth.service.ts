import { HttpException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt/dist';
import { HttpStatus } from '@nestjs/common/enums';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { User } from 'src/users/users.model';
import * as bcrypt from 'bcryptjs'
import * as cryptoJs from "crypto-js";
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {

    constructor(private userService: UsersService, 
                private jwtService: JwtService) {}

    async login(userDto: CreateUserDto) {
        const user = await this.validateUser(userDto);
        return this.generateToken(user);
    }

    // получаем логин и формируем H
    async login1(userDto: CreateUserDto) {
        let candidate = await this.userService.getUserByEmail(userDto.email);
        
        if(candidate){
            const H = (this.getRandomInt(99) + 1).toString();
            candidate.H = H;
            await candidate.save()
            return {H};
        }
        throw new HttpException('Неверное имя пользователя или пароль', HttpStatus.BAD_REQUEST); 
    }

    // получаем H и сравниваем его с H из бд
    async login2(userDto: CreateUserDto) {
        const user = await this.userService.getUserByEmail(userDto.email);
        
        const passwordHash = cryptoJs.MD5(user.password).toString()
        const hHash = cryptoJs.MD5(user.H).toString()
        const newH = cryptoJs.MD5(hHash + passwordHash).toString();

        if(newH == userDto.H){
            return {message: 'Соединение успешно установлено'}
        }
        throw new HttpException('H не совпадают', HttpStatus.BAD_REQUEST); 
    }

    async registration(userDto: CreateUserDto) {
        const candidate = await this.userService.getUserByEmail(userDto.email);
        if (candidate){
            throw new HttpException('Пользователь с таким email уже существует', HttpStatus.BAD_REQUEST);
        }
        // const hashPassword = await bcrypt.hash(userDto.password, 5)
        // const user = await this.userService.createUser({...userDto, password: hashPassword});
        const user = await this.userService.createUser(userDto);

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

    getRandomInt(max: number) {
        return Math.floor(Math.random() * max);
    }
}
