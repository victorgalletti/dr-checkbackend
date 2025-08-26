// dr-checkbackend/src/auth/auth.controller.ts
// dr-checkbackend/src/auth/auth.controller.ts
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { SignInDto } from './dto/sign-in.dto';

@Controller('auth')
export class AuthController {
  @Post('google/register')
  handleGoogleRegister(@Body('token') token: string) {
    return this.authService.handleGoogleRegister(token);
  }
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  signIn(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto.email, signInDto.password);
  }

  @Post('register')
  signUp(@Body() createUserDto: CreateUserDto) {
    const { email, password, fullName } = createUserDto;
    return this.authService.signUp(email, password, fullName);
  }

  @Post('google/login')
  handleGoogleLogin(@Body('token') token: string) {
    return this.authService.handleGoogleLogin(token);
  }
}
