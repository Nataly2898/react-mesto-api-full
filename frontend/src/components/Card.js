import React from "react";
import CurrentUserContext from "../contexts/CurrentUserContext";

function Card({ card, onCardClick, onCardLike, onCardDelete }) {
  // Подписка на контекст
  const currentUser = React.useContext(CurrentUserContext);
  // Определяем, являемся ли мы владельцем текущей карточки
  const isOwn = card.owner._id === currentUser._id;

  // Создаём переменную, которую после зададим в `className` для кнопки удаления
  const cardDeleteButtonClassName = isOwn
    ? "card__button-trash card__button-trash_visible"
    : "card__button-trash card__button-trash_hidden";

  // Определяем, есть ли у карточки лайк, поставленный текущим пользователем
  const isLiked = card.likes.some((i) => i._id === currentUser._id);

  // Создаём переменную, которую после зададим в `className` для кнопки лайка
  const cardLikeButtonClassName = isLiked
    ? "card__like card__like_active"
    : "card__like";

  function handleCardClick() {
    onCardClick(card);
  }

  function handleLikeClick() {
    onCardLike(card);
  }

  function handleDeleteClick() {
    onCardDelete(card);
  }

  return (
    <div className="card">
      <img
        src={card.link}
        alt={card.name}
        className="card__image"
        onClick={handleCardClick}
      />
      <div className="card__container">
        <h2 className="card__title">{card.name}</h2>
        <div className="card__like-contain">
          <button
            className={cardLikeButtonClassName}
            type="button"
            onClick={handleLikeClick}
          ></button>
          <span className="card__likes-number">{card.likes.length}</span>
        </div>
      </div>
      <button
        className={cardDeleteButtonClassName}
        type="button"
        aria-label="Удаление карточки"
        onClick={handleDeleteClick}
      ></button>
    </div>
  );
}

export default Card;
