import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { UserType } from 'src/types/types';
@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string) {
    const user = await this.userService.findOne(email);

    if (!user) {
      return null;
    }

    const passwordsIsMatch = await argon2.verify(user.password, pass);
    if (passwordsIsMatch) {
      return user;
    }
    throw new UnauthorizedException('Не верный пароль');
  }

  login(user: UserType) {
    const { id, email } = user;

    return { id, email, token: this.jwtService.sign({ id, email }) };
  }
}
