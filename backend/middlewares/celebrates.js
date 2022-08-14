const { celebrate, Joi } = require('celebrate');
const validator = require('validator');

function isUrl(link) {
  const result = validator.isURL(link);
  if (result) {
    return link;
  }
  throw new Error('Невалидный URL');
}

module.exports.signUp = celebrate({
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    password: Joi.string().required().min(8),
    name: Joi.string().min(2).max(30),
    about: Joi.string().min(2).max(30),
    avatar: Joi.string().custom(isUrl),
  }),
});

module.exports.signIn = celebrate({
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    password: Joi.string().required().min(8),
  }),
});

module.exports.userId = celebrate({
  params: Joi.object().keys({
    userId: Joi.string().hex().length(24),
  }),
});

module.exports.profileUpdate = celebrate({
  body: Joi.object().keys({
    name: Joi.string().min(2).max(30),
    about: Joi.string().min(2).max(30),
  }),
});

module.exports.avatarUpdate = celebrate({
  body: Joi.object().keys({
    avatar: Joi.string().required().custom(isUrl),
  }),
});

module.exports.cardCreation = celebrate({
  body: Joi.object().keys({
    name: Joi.string().required().min(2).max(30),
    link: Joi.string().required().custom(isUrl),
  }),
});

module.exports.cardId = celebrate({
  params: Joi.object().keys({
    cardId: Joi.string().hex().length(24),
  }),
});
