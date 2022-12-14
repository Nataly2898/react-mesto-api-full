const Card = require('../models/card');
const IncorrectRequestError = require('../errors/IncorrectRequestError');
const ForbiddenError = require('../errors/ForbiddenError');
const NotFoundError = require('../errors/NotFoundError');

// Получение карточек
module.exports.getCards = (req, res, next) => {
  Card.find({})
    .then((cards) => res.status(200).send(cards))
    .catch(next);
};
// Создание новой карточки
module.exports.createCard = (req, res, next) => {
  const { name, link } = req.body;

  Card.create({ name, link, owner: req.user._id })
    .then((card) => res.send(card))
    .catch((err) => {
      if (err.name === 'ValidationError') {
        return next(new IncorrectRequestError('Переданы неверные данные.'));
      }
      return next(err);
    });
};
// Удаление карточки
module.exports.deleteCard = (req, res, next) => {
  const { cardId } = req.params;
  const { _id } = req.user;
  Card.findById(cardId)
    // eslint-disable-next-line consistent-return
    .then((card) => {
      if (!card) {
        return next(new NotFoundError('Карточка не найдена.'));
      }
      if (card.owner.valueOf() !== _id) {
        return next(new ForbiddenError('Нельзя удалить чужую карточку!'));
      }
      Card.findByIdAndRemove(cardId)
        .then((deletedCard) => res.send(deletedCard))
        .catch(next);
    });
};
// Поставить лайк
module.exports.likeCard = (req, res, next) => {
  Card.findByIdAndUpdate(
    req.params.cardId,
    { $addToSet: { likes: req.user._id } },
    { new: true },
  )
    .then((card) => {
      if (!card) {
        return next(new NotFoundError('Карточка не найдена.'));
      }
      return res.send(card);
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        return next(new IncorrectRequestError('Некорректые данные карточки'));
      }
      return next(err);
    });
};
// Удалить лайк
module.exports.dislikeCard = (req, res, next) => {
  Card.findByIdAndUpdate(
    req.params.cardId,
    { $pull: { likes: req.user._id } },
    { new: true },
  )
    .then((card) => {
      if (!card) {
        next(new NotFoundError('Карточка не найдена. Лайк не удалось убрать.'));
      } else res.send(card);
    })
    .catch((err) => {
      if (err.name === 'CastError') {
        return next(new IncorrectRequestError('Некорректые данные карточки'));
      }
      return next(err);
    });
};
