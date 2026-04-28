import userService from '../services/user.service.js';

class UserController {
  async registration(req, res) {
    try {
      const { name, email, password } = req.body;
      const userData = await userService.registration(name, email, password);

      return res.json(userData);
    } catch (e) {
      res.status(400).json({ message: e.message });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const userData = await userService.login(email, password);

      res.cookie('token', userData.token, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
      });

      return res.json(userData);
    } catch (e) {
      res.status(401).json({ message: e.message });
    }
  }

  async activate(req, res) {
    try {
      const { token } = req.params;
      const jwtToken = await userService.activate(token);

      res.cookie('token', jwtToken, {
        maxAge: 24 * 60 * 60 * 1000,
        httpOnly: true,
      });

      return res.redirect(`${process.env.CLIENT_URL}/profile?activated=true`);
    } catch (e) {
      res.status(400).json({ message: e.message });
    }
  }

  async logout(req, res) {
    try {
      res.clearCookie('token');

      return res.json({ message: 'Вышли из системы' });
    } catch (e) {
      res.status(500).json({ message: 'Ошибка логаута' });
    }
  }

  async getProfile(req, res) {
    try {
      const user = await userService.getProfile(req.user.userId);

      return res.json(user);
    } catch (e) {
      res.status(500).json({ message: e.message });
    }
  }

  async updatePassword(req, res) {
    try {
      const { oldPassword, newPassword } = req.body;

      await userService.updatePassword(
        req.user.userId,
        oldPassword,
        newPassword,
      );

      return res.json({ message: 'Пароль успешно обновлен' });
    } catch (e) {
      res.status(400).json({ message: e.message });
    }
  }

  async updateEmail(req, res) {
    try {
      const { password, newEmail } = req.body;

      await userService.updateEmail(req.user.userId, password, newEmail);

      return res.json({ message: 'Инструкции отправлены на почту' });
    } catch (e) {
      res.status(400).json({ message: e.message });
    }
  }
}

export default new UserController();
