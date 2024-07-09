import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { LoginUserDto } from './dto/login-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

  private logger = new Logger('AuthService')

  constructor(
    private jwtService : JwtService
  ){
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('MongoDB connected.')
  }


  async findUser( email : string ){
    const user = await this.user.findFirst({
      where : {
        email : email
      }
    })

    return user;
  }

  async loginUser( loginUserDto : LoginUserDto ){

    const { email, password } = loginUserDto;

    const user = await this.findUser(email)

    if(!user) throw new RpcException({ status : 400, message : 'User not exist' })
    if(!bcrypt.compareSync(password, user.password)) throw new RpcException({ status : 400, message : 'Invalid credentials' })

    const { password: __, ...rest } = user;

    return {
      user : rest,
      token : await this.signJWT(rest)
    }
  }

  async registerUser( registerUserDto : RegisterUserDto ){

    const { name, email, password } = registerUserDto;


    try {

      if(await this.findUser(email)) throw new RpcException({ status : 400, message : 'User already exist' })

      const user = await this.user.create({
        data : {
          name,
          email,
          password : bcrypt.hashSync(password, 10)
        }
      })
    
      const { password : __ , ...rest } = user;

      return {
        user : rest,
        token : await this.signJWT(rest)
      }
  
    } catch (error) {
      throw new RpcException({
        status : 400,
        message : error.message
      })
    }
  }

  async verifyToken( token : string ){

    try {
      
      const { sub, iat, exp, ...user } = this.jwtService.verify( token, { secret : envs.jwt_secret });

      return {
        user,
        token: await this.signJWT(user)
      }


    } catch (error) {
      throw new RpcException({
        status : 401,
        message : 'Invalid token'
      })
    }


  }

  async signJWT( payload : JwtPayload ){
    return this.jwtService.sign(payload)
  }

}
