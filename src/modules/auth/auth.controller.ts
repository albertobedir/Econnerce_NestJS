import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Public } from 'src/common/decorators';
import { GetUser, GetUserId } from 'src/common/decorators/user.decorator';
import { RtGuard } from 'src/common/guards';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  register(@Body() dto: AuthDto) {
    return this.authService.register(dto);
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() dto: AuthDto) {
    return this.authService.login(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Get('get-session')
  getSession(@GetUser('sub') sub: string) {
    return sub;
  }

  @Public()
  @UseGuards(RtGuard)
  @HttpCode(HttpStatus.OK)
  @Get('refresh')
  refreshSession(
    @GetUser('refreshToken') rt: string,
    @GetUserId() sub: string,
  ) {
    return this.authService.refreshSession(sub, rt);
  }
}
