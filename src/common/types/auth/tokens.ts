import { UserRole } from '@prisma/client';

export type JwtPayload = {
  sub: string;
  email: string;
  role: UserRole;
};

export type Tokens = {
  access_token: string;
  refresh_token: string;
};
