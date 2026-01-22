import { IsEmail } from 'class-validator';

export class VerifyEmailDto {
  @IsEmail()
  email: string;
}

export class ResendVerificationEmailDto {
  @IsEmail()
  email: string;
}
