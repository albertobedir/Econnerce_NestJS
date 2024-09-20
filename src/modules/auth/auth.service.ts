import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { JwtPayload, Tokens } from 'src/common/types/auth';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  register = async (dto: AuthDto) => {
    const hash = await argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      const tokens = await this.getTokens({
        email: user.email,
        role: user.userRole,
        sub: user.id,
      });

      await this.hashedRt(user.id, tokens.refresh_token);

      return {
        tokens,
        message: 'User created successfully',
        userId: user.id,
      };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('Email already exists');
      }
      throw new HttpException(
        'Something went wrong during registration',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  };

  login = async (dto: AuthDto) => {
    const exist = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!exist) throw new ForbiddenException('user not found');

    const passMatch = await argon.verify(exist.hash, dto.password);
    if (!passMatch) throw new ForbiddenException('password is wrong');

    const tokens = await this.getTokens({
      email: exist.email,
      role: exist.userRole,
      sub: exist.id,
    });
    await this.hashedRt(exist.id, tokens.refresh_token);

    return {
      message: 'User logged successfully',
      tokens,
    };
  };

  logout = async (sub: string): Promise<boolean> => {
    await this.prisma.user.updateMany({
      where: { id: sub, hashedRt: { not: null } },
      data: { hashedRt: null },
    });

    return true;
  };

  getTokens = async ({ email, role, sub }: JwtPayload): Promise<Tokens> => {
    const payload: JwtPayload = {
      sub,
      email,
      role,
    };

    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '1m',
      }),
      this.jwt.signAsync(payload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token,
      refresh_token,
    };
  };

  hashedRt = async (userId: string, rt: string) => {
    const hashedRt = await argon.hash(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt },
    });
  };

  refreshSession = async (id: string, rt: string): Promise<Tokens> => {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatch = await argon.verify(user.hashedRt, rt);
    if (!rtMatch) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens({
      email: user.email,
      role: user.userRole,
      sub: id,
    });

    await this.hashedRt(id, tokens.refresh_token);

    return tokens;
  };

  getSession = async (sub: string): Promise<User> => {
    const user = await this.prisma.user.findUnique({ where: { id: sub } });
    if (!user) throw new NotFoundException('User not found.');

    delete user.hash, delete user.hashedRt;

    return user;
  };
}
