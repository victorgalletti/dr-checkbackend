import {
  Injectable,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  // LOGIN COM EMAIL E SENHA
  async signIn(email: string, pass: string) {
    const user = await this.prisma.user.findFirst({ where: { email } });

    if (!user || !user.password) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    const isPasswordMatching = await bcrypt.compare(pass, user.password);
    if (!isPasswordMatching) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    return this.generateJwt(user.id, user.email ?? '');
  }

  // CADASTRO COM EMAIL E SENHA
  async signUp(email: string, password: string, fullName: string) {
    const existingUser = await this.prisma.user.findFirst({ where: { email } });

    if (existingUser) {
      throw new ConflictException('Um usuário com este e-mail já existe.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        fullName,
        provider: 'email',
      },
    });

    // Retorna o usuário criado, sem a senha
    const { password: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  }

  // GERAÇÃO DE JWT
  private async generateJwt(userId: string, email: string) {
    const payload = { sub: userId, email };
    const accessToken = await this.jwtService.signAsync(payload);
    return { access_token: accessToken };
  }
}
