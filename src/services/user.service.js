import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import User from '../models/user.model.js';
import emailService from './email.service.js';
import tokenService from './token.service.js';

class UserService {
  async registration(name, email, password) {
    const candidate = await User.findOne({ where: { email } });

    if (candidate) {
      throw new Error(`Пользователь с email ${email} уже существует`);
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const activationToken = uuidv4();

    const user = await User.create({
      name,
      email,
      password: hashPassword,
      activationToken,
    });

    const activationLink = `${process.env.API_URL}/api/activate/${activationToken}`;

    await emailService.sendActivationMail(email, activationLink);

    return {
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  async activate(token) {
    const user = await User.findOne({ where: { activationToken: token } });

    if (!user) {
      throw new Error('Некорректная ссылка активации');
    }

    user.isActive = true;
    user.activationToken = null;
    await user.save();

    return tokenService.generateToken({ userId: user.id });
  }

  async login(email, password) {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error('Пользователь не найден');
    }

    if (!user.isActive) {
      throw new Error('Аккаунт не подтвержден. Проверьте почту');
    }

    const isPassEquals = await bcrypt.compare(password, user.password);

    if (!isPassEquals) {
      throw new Error('Неверный пароль');
    }

    const token = tokenService.generateToken({ userId: user.id });

    return {
      token,
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  async forgotPassword(email) {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      throw new Error('Пользователь не найден');
    }

    const resetToken = uuidv4();

    user.resetToken = resetToken;
    await user.save();

    const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    await emailService.sendNotification(
      email,
      `Ссылка для сброса пароля: ${resetLink}`,
    );
  }

  async updatePassword(userId, oldPassword, newPassword) {
    const user = await User.findByPk(userId);
    const isPassEquals = await bcrypt.compare(oldPassword, user.password);

    if (!isPassEquals) {
      throw new Error('Старый пароль неверный');
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
  }

  async updateEmail(userId, password, newEmail) {
    const user = await User.findByPk(userId);
    const isPassEquals = await bcrypt.compare(password, user.password);

    if (!isPassEquals) {
      throw new Error('Неверный пароль');
    }

    const oldEmail = user.email;
    const activationToken = uuidv4();

    user.pendingEmail = newEmail;
    user.activationToken = activationToken;
    await user.save();

    await emailService.sendNotification(
      oldEmail,
      `Ваш email меняется на ${newEmail}. Если это не вы — смените пароль.`,
    );

    const link = `${process.env.API_URL}/api/activate-new-email/${activationToken}`;

    await emailService.sendActivationMail(newEmail, link);
  }
}

export default new UserService();
