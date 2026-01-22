import { ApiProperty } from "@nestjs/swagger";
import { IsString, MinLength } from "class-validator";

export class ResetPasswordDto {
  @ApiProperty({ example: 'reset-', description: 'Password reset otp' })
  @IsString()
  otp: string;

  @ApiProperty({ example: 'newStrongPassword123', description: 'New password' })
  @IsString()
  @MinLength(6)
  password: string;
}