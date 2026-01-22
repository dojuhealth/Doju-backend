import { ApiProperty } from "@nestjs/swagger";
import { IsEmail } from "class-validator";

export class ForgotPasswordDto {

    @ApiProperty({ example: 'john@example.com',
        description: 'The email of the user who forgot their password' })
    @IsEmail()
    email: string;
}
