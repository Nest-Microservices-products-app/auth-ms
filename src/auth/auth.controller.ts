import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  

  @MessagePattern('auth.login.user')
  loginUser( @Payload() loginUserDto : LoginUserDto ) {
    return this.authService.loginUser(loginUserDto);
  }

  @MessagePattern('auth.register.user')
  registerUser( @Payload() registerUserDto : RegisterUserDto ) {
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern('auth.verify.user')
  verifyUser( @Payload() token : string ) {
    return this.authService.verifyToken(token);
  }


}
