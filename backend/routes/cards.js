const router = require('express').Router();
const celebrates = require('../middlewares/celebrates');

const {
  getCards,
  createCard,
  deleteCard,
  likeCard,
  dislikeCard,
} = require('../controllers/cards');

router.get('/', getCards);
router.post('/', celebrates.cardCreation, createCard);
router.delete('/:cardId', celebrates.cardId, deleteCard);
router.put('/:cardId/likes', celebrates.cardId, likeCard);
router.delete('/:cardId/likes', celebrates.cardId, dislikeCard);

module.exports = router;
