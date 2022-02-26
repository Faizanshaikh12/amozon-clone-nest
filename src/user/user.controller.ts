import {Controller, Get, Param} from '@nestjs/common';
import {UserDetails} from "./user.interface";
import {UserService} from "./user.service";

@Controller('user')
export class UserController {
    constructor(private userService: UserService) {
    }

    @Get(':id')
    async getUser(@Param('id') id: string): Promise<UserDetails> {
        return this.userService.findById(id);
    }
}
