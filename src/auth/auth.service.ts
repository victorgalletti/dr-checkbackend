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
  async handleGoogleRegister(supabaseToken: string) {
    // 1. Validar o token do Supabase
    let supabaseUser;
    try {
      supabaseUser = await this.jwtService.verifyAsync(supabaseToken, {
        secret: process.env.SUPABASE_JWT_SECRET,
      });
    } catch (error) {
      throw new UnauthorizedException('Token do Supabase inválido');
    }

    const { sub: providerId, email, user_metadata } = supabaseUser;
    const fullName = user_metadata?.full_name;

    // Verifica se já existe usuário com providerId
    let user = await this.prisma.user.findFirst({
      where: { providerId: providerId },
    });
    if (user) {
      throw new ConflictException(
        'Usuário já cadastrado com essa conta Google.',
      );
    }

    // Verifica se já existe usuário com email
    const userByEmail = await this.prisma.user.findFirst({ where: { email } });
    if (userByEmail) {
      // Sincroniza a conta Google ao usuário existente
      user = await this.prisma.user.update({
        where: { id: userByEmail.id },
        data: { provider: 'google', providerId: providerId },
      });
    } else {
      // Cria novo usuário Google
      user = await this.prisma.user.create({
        data: {
          email,
          fullName,
          provider: 'google',
          providerId: providerId,
        },
      });
    }

    // Gera e retorna o token JWT
    const payload = { sub: user.id, email: user.email };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '1d',
    });
    return { access_token: accessToken };
  }
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async handleGoogleLogin(supabaseToken: string) {
    // 1. Validar o token do Supabase
    let supabaseUser;
    try {
      supabaseUser = await this.jwtService.verifyAsync(supabaseToken, {
        secret: process.env.SUPABASE_JWT_SECRET,
      });
    } catch (error) {
      throw new UnauthorizedException('Token do Supabase inválido');
    }

    const { sub: providerId, email, user_metadata } = supabaseUser;
    const fullName = user_metadata?.full_name;

    // 2. Lógica de Login Google
    // Tenta encontrar um usuário pelo ID do provedor Google
    const user = await this.prisma.user.findUnique({
      where: { providerId: providerId },
    });
    if (!user) {
      throw new UnauthorizedException('Usuário Google não encontrado.');
    }
    // 3. Gerar e retornar o token JWT do nosso backend
    const payload = { sub: user.id, email: user.email };
    const accessToken = await this.jwtService.signAsync(payload, {
      secret: process.env.JWT_SECRET,
      expiresIn: '1d',
    });
    return { access_token: accessToken };
  }

  async signIn(email: string, pass: string): Promise<any> {
    const user = await this.prisma.user.findFirst({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    if (!user.password) {
      throw new UnauthorizedException('Credenciais inválidas');
    }
    const isPasswordMatching = await bcrypt.compare(pass, user.password);

    if (!isPasswordMatching) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    // Se a senha estiver correta, aqui você geraria e retornaria um token JWT.
    // Por enquanto, vamos retornar o usuário sem a senha.
    const { password, ...result } = user;
    return result; // Futuramente, isso retornará { access_token: '...' }
  }

  async signUp(email: string, password: string, fullName: string) {
    try {
      // 1. Verificar se o usuário já existe
      const existingUser = await this.prisma.user.findFirst({
        // Use seu modelo do Prisma aqui (ex: Paciente, User)
        where: { email },
      });

      if (existingUser) {
        throw new ConflictException('Um usuário com este e-mail já existe.');
      }

      // 2. Hashear a senha
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // 3. Criar o novo usuário no banco de dados
      const user = await this.prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          fullName,
        },
      });

      // 4. Retornar mensagem informando que a senha é obrigatória
      return {
        message: 'A senha é obrigatória e não será retornada.',
      };
    } catch (error) {
      console.error('Erro no signUp:', error);
      throw error;
    }
  }
}
