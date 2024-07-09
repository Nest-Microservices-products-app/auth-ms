import { IsEmail, IsString, IsStrongPassword, MinLength } from "class-validator";

export class RegisterUserDto {

  @IsString()
  @MinLength(1)
  name : string;

  @IsString()
  @IsEmail()
  email : string;

  @IsString()
  @IsStrongPassword()
  password : string;

}