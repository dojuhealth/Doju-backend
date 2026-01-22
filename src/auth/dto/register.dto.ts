import { IsEmail, IsEnum, IsNotEmpty, IsOptional, MinLength } from 'class-validator';
import { UserRole } from 'src/users/enums/user.enum';

export class RegisterDto {
    @IsNotEmpty()
    fullName: string;

    @IsEmail()
    email: string;

    @MinLength(8)
    password: string;

    @IsEnum(UserRole)
    role: UserRole

    @IsNotEmpty()
    phoneNumber: string;

    @IsNotEmpty()
    address: string;

    @IsNotEmpty()
    country: string;

    @IsOptional()
    BusinessName?: string;
}