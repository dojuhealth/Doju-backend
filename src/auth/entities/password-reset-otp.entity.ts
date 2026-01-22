import { User } from "src/users/entities/user.entity";
import { Entity, Column, PrimaryGeneratedColumn, ManyToOne, CreateDateColumn, UpdateDateColumn, JoinColumn } from "typeorm";

@Entity({ name: 'password_reset_otps' })
export class PasswordResetOtp {
    @PrimaryGeneratedColumn('uuid')
    @Column ({name: 'user_id'})
    id: string;

    @ManyToOne (() => User, { onDelete: 'CASCADE' })
     @JoinColumn({ name: 'user_id' })
    user: User;

    @Column ({ unique: true})
    otp: string;

     @Column({ name: 'expires_at' })
  expiresAt: Date;

   @Column({ name: 'is_used', default: false })
  isUsed: boolean;

}