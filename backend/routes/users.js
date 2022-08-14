const router = require('express').Router();
const celebrates = require('../middlewares/celebrates');

const {
  getUsers,
  getCurrentUser,
  getUserById,
  updateProfile,
  updateAvatar,
} = require('../controllers/users');

router.get('/', getUsers);
router.get('/me', getCurrentUser);
router.get('/:userId', celebrates.userId, getUserById);
router.patch('/me', celebrates.profileUpdate, updateProfile);
router.patch('/me/avatar', celebrates.avatarUpdate, updateAvatar);

module.exports = router;
