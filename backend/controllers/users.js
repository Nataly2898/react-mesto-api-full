const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const ExistingEmailError = require('../errors/ExistingEmailError');
const IncorrectRequestError = require('../errors/IncorrectRequestError');
const NotFoundError = require('../errors/NotFoundError');
const NotAuthorizationError = require('../errors/NotAuthorizationError');
const config = require('../middlewares/config');

// Создание нового пользователя
module.exports.createUser = (req, res, next) => {
  const {
    email, password, about, avatar, name,
  } = req.body;

  User.findOne({ email })
    .then(() => {
      if (!email || !password) {
        throw new IncorrectRequestError('Неправильный логин или пароль.');
      }
      return bcrypt.hash(password, 10);
    })
    .then((hash) => User.create({
      email,
      password: hash,
      name,
      about,
      avatar,
    }))
    .then((user) => res.status(201).send({
      name: user.name,
      about: user.about,
      avatar: user.avatar,
      _id: user._id,
      email: user.email,
    }))
    .catch((err) => {
      if (err.name === 'MongoServerError' && err.code === 11000) {
        throw new ExistingEmailError('Пользователь с таким email уже существует');
      } else if (err.name === 'ValidationError') {
        throw new IncorrectRequestError('Ошибка валидации данных');
      } else next(err);
    })
    .catch(next);
};

// Аутентификация пользователя
module.exports.login = (req, res, next) => {
  const { email, password } = req.body;
  return User.findUserByCredentials(email, password)
    .then((user) => {
      // создадим токен
      const token = jwt.sign(
        { _id: user._id },
        config.JWT_SECRET,
        {
          expiresIn: '7d',
        },
      );

      // вернём токен
      res.send({ token });
    })
    .catch(() => {
      throw new NotAuthorizationError('Неверный email или пароль.');
    })
    .catch(next);
};

// возвращает информацию о текущем пользователе
module.exports.getCurrentUser = (req, res, next) => {
  const { _id } = req.user;
  User.findById(_id).then((user) => {
    // проверяем, есть ли пользователь с таким id
    if (!user) {
      return next(new NotFoundError('Пользователь не найден.'));
    }

    // возвращаем пользователя, если он есть
    return res.send(user);
  }).catch(next);
};

// Получение пользователей
module.exports.getUsers = (req, res, next) => {
  User.find({})
    .then((users) => res.status(200).send(users))
    .catch(next);
};

// Получение пользователя по его id
module.exports.getUserById = (req, res, next) => {
  User.findById(req.params.userId)
    .then((user) => {
      if (!user) {
        throw new NotFoundError('Пользователь не найден');
      } else res.send(user);
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        throw new IncorrectRequestError('Некорректный айди');
      }
      next(err);
    })
    .catch(next);
};

// Обновление информации о пользователе
module.exports.updateProfile = (req, res, next) => {
  const { name, about } = req.body;
  User.findByIdAndUpdate(
    req.user._id,
    { name, about },
    { new: true, runValidators: true },
  )
    .then((user) => res.send(user))
    .catch((err) => {
      if (err.name === 'ValidationError') {
        throw new IncorrectRequestError('Неверный тип данных.');
      }
      next(err);
    })
    .catch(next);
};

// Обновление аватара пользователя
module.exports.updateAvatar = (req, res, next) => {
  const { avatar } = req.body;
  User.findByIdAndUpdate(
    req.user._id,
    { avatar },
    { new: true, runValidators: true },
  )
    .then((user) => res.status(200).send(user))
    .catch((err) => {
      if (err.name === 'ValidationError') {
        throw new IncorrectRequestError('Неверная ссылка');
      }
      next(err);
    })
    .catch(next);
};
