const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const ExistingEmailError = require('../errors/ExistingEmailError');
const IncorrectRequestError = require('../errors/IncorrectRequestError');
const NotFoundError = require('../errors/NotFoundError');
const NotAuthorizationError = require('../errors/NotAuthorizationError');

const { NODE_ENV, JWT_SECRET } = process.env;

// Создание нового пользователя
module.exports.createUser = (req, res, next) => {
  const {
    email, password, about, avatar, name,
  } = req.body;

  bcrypt.hash(password, 10)
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
        next(new ExistingEmailError('Пользователь с таким email уже существует'));
      } else if (err.name === 'ValidationError') {
        next(new IncorrectRequestError('Ошибка валидации данных'));
      } else next(err);
    });
};

// Аутентификация пользователя
module.exports.login = (req, res, next) => {
  const { email, password } = req.body;
  return User.findUserByCredentials(email, password)
    .then((user) => {
      // создадим токен
      const token = jwt.sign(
        { _id: user._id },
        NODE_ENV === 'production' ? JWT_SECRET : 'some-secret-key',
        {
          expiresIn: '7d',
        },
      );

      // вернём токен
      res.send({ token });
    })
    .catch(() => next(new NotAuthorizationError('Неверный email или пароль.')));
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
  });
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
        next(new NotFoundError('Пользователь не найден'));
      } else res.send(user);
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        next(IncorrectRequestError('Некорректный айди'));
      }
      return next(err);
    });
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
        return next(new IncorrectRequestError('Неверный тип данных.'));
      }
      return next(err);
    });
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
        return next(new IncorrectRequestError('Неверная ссылка'));
      }
      return next(err);
    });
};
