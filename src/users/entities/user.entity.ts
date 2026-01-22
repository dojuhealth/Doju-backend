import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { UserRole } from '../enums/user.enum';

@Entity({ name: 'users' })
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  fullName: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password?: string;

  @Column({ nullable: true })
  phoneNumber?: string;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.BUYER,
  })
  role: UserRole;

  // 🔹 Google OAuth fields
  @Column({ nullable: true })
  googleId?: string;

  // 🔹 Email verification fields
  @Column({ default: false })
  emailVerified: boolean;

  @Column({ nullable: true })
  verificationOtp?: string;

  @Column({ nullable: true })
  verificationOtpExpires?: Date;

  // 🔹 Password reset fields
  @Column({ nullable: true })
  passwordResetOtp?: string;

  @Column({ nullable: true })
  passwordResetOtpExpires?: Date;

  // 🔹 Seller-specific (can be null for buyers)
  @Column({ nullable: true })
  companyName?: string;

  @Column({ nullable: true })
  address?: string;

  @Column({ nullable: true })
  licenseNumber?: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
