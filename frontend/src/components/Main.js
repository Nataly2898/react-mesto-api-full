import React from "react";
import logoAva from "../images/kusto.jpg";
import Card from "./Card";
import CurrentUserContext from "../contexts/CurrentUserContext";

function Main({
  onEditAvatar,
  onEditProfile,
  onAddPlace,
  onCardClick,
  cards,
  onCardLike,
  onCardDelete,
}) {
  // Подписка на контекст
  const currentUser = React.useContext(CurrentUserContext);

  return (
    <main className="content">
      <section className="profile">
        <img
          src={currentUser.avatar ?? logoAva}
          alt={`Аватар пользователя ${currentUser.name}`}
          className="profile__avatar"
        />
        <button
          className="profile__avatar-button"
          onClick={onEditAvatar}
        ></button>

        <div className="profile__info">
          <div className="profile__text">
            <h1 className="profile__title">{currentUser.name}</h1>
            <button
              className="profile__edit-button"
              type="button"
              aria-label="Открыть"
              onClick={onEditProfile}
            ></button>
          </div>
          <p className="profile__description">{currentUser.about}</p>
        </div>
        <button
          className="profile__add-button"
          type="button"
          aria-label="Загрузить фото"
          onClick={onAddPlace}
        ></button>
      </section>

      <section className="cards cards__list">
        {cards.map((card) => (
          <Card
            card={card}
            key={card._id}
            onCardClick={onCardClick}
            onCardLike={onCardLike}
            onCardDelete={onCardDelete}
          />
        ))}
      </section>
    </main>
  );
}

export default Main;
