import React from "react";
import PopupWithForm from "./PopupWithForm";

function AddPlacePopup({ isOpen, onClose, onAddPlace }) {
  const [name, setName] = React.useState("");
  const [link, setLink] = React.useState("");

  // Сброс значений инпутов
  React.useEffect(() => {
    setName("");
    setLink("");
  }, [isOpen]);

  function changeCardName(name) {
    setName(name.target.value);
  }

  function changeCardLink(link) {
    setLink(link.target.value);
  }

  function handleSubmit(event) {
    event.preventDefault();
    onAddPlace({
      name,
      link,
    });
  }

  return (
    <PopupWithForm
      name="add-card"
      title="Новое место"
      buttonText="Создать"
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
    >
      <label className="form__field">
        <input
          id="inputTitleAdd"
          name="inputTitleAdd"
          className="popup__input popup__input_type_title"
          type="text"
          placeholder="Название"
          minLength="2"
          maxLength="30"
          value={name}
          onChange={changeCardName}
          required
        />
        <span className="popup__form-error inputTitleAdd-error"></span>
      </label>
      <label className="form__field">
        <input
          id="inputSubtitleAdd"
          name="inputSubtitleAdd"
          className="popup__input popup__input_type_link"
          type="url"
          placeholder="Ссылка на картинку"
          value={link}
          onChange={changeCardLink}
          required
        />
        <span className="popup__form-error inputSubtitleAdd-error"></span>
      </label>
    </PopupWithForm>
  );
}

export default AddPlacePopup;
