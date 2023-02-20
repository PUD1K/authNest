import { Body, Controller, Post } from '@nestjs/common';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {

    constructor(private authService: AuthService) {}

    @Post('/login')
    login(@Body() userDto: CreateUserDto){
        return this.authService.login(userDto);
    }

    @Post('/registration')
    registration(@Body() userDto: CreateUserDto){
        return this.authService.registration(userDto);
    }

    @Post('/login1')
    login1(@Body() userDto: CreateUserDto){
        return this.authService.login1(userDto);
    }

    @Post('/login2')
    login2(@Body() userDto: CreateUserDto){
        return this.authService.login2(userDto);
    }
}
