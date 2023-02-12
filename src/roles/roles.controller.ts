import { Controller, Body, Param, Post, Get} from '@nestjs/common';
import { ApiOperation, ApiResponse } from '@nestjs/swagger/dist';
import { CreateRoleDto } from './dto/create-role.dto';
import { Role } from './roles.model';
import { RolesService } from './roles.service';

@Controller('roles')
export class RolesController {

    constructor(private rolesService: RolesService){}

    @ApiOperation({summary: 'Создание роли'})
    @ApiResponse({status: 200, type: Role})
    @Post()
    create(@Body() dto: CreateRoleDto){
        return this.rolesService.createRole(dto);
    }

    @ApiOperation({summary: 'Получение роли'})
    @ApiResponse({status: 200, type: Role})
    @Get('/:value')
    getByValue(@Param('value') value: string){
        return this.rolesService.getRoleByValue(value);
    }
}
