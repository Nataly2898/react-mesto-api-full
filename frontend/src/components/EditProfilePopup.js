import React from "react";
import PopupWithForm from "./PopupWithForm";
import CurrentUserContext from "../contexts/CurrentUserContext";

function EditProfilePopup({ isOpen, onClose, onUpdateUser }) {
  // Подписка на контекст
  const currentUser = React.useContext(CurrentUserContext);
  const [name, setUserName] = React.useState("");
  const [description, setUserDescription] = React.useState("");

  // Сброс инпутов
  React.useEffect(() => {
    setUserName(currentUser.name);
    setUserDescription(currentUser.about);
  }, [currentUser, isOpen]);

  // Обработчик изменения инпута
  function handleChangeUserName(name) {
    setUserName(name.target.value);
  }

  // Обработчик изменения инпута
  function handleChangeUserDescription(description) {
    setUserDescription(description.target.value);
  }

  function handleSubmit(event) {
    event.preventDefault();
    onUpdateUser({
      name,
      about: description,
    });
  }

  return (
    <PopupWithForm
      name="edit-profile"
      title="Редактировать профиль"
      buttonText="Сохранить"
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
    >
      <label className="form__field">
        <input
          id="name"
          name="name"
          className="popup__input popup__input_type_name"
          type="text"
          value={name ?? ""}
          onChange={handleChangeUserName}
          minLength="2"
          maxLength="40"
          placeholder="Имя пользователя"
          required
        />
        <span className="popup__form-error inputTitle-error"></span>
      </label>
      <label className="form__field">
        <input
          id="about"
          name="about"
          className="popup__input popup__input_type_description"
          type="text"
          value={description ?? ""}
          onChange={handleChangeUserDescription}
          minLength="2"
          maxLength="200"
          placeholder="О себе"
          required
        />
        <span className="popup__form-error inputSubtitle-error"></span>
      </label>
    </PopupWithForm>
  );
}

export default EditProfilePopup;
