import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { JwtPayload, Tokens } from 'src/common/types/auth';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

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
      return {
        message: 'User registered successfully',
        userId: user.id,
      };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new HttpException('Email already exists', HttpStatus.BAD_REQUEST);
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
    await this.hashedRt(tokens.refresh_token, exist.id);

    return tokens;
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
        expiresIn: '15m',
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

  hashedRt = async (rt: string, userId: string) => {
    const hashedRt = await argon.hash(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt },
    });
  };
}
