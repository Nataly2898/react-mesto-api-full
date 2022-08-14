import React from "react";
import PopupWithForm from "./PopupWithForm";

function EditAvatarPopup({ isOpen, onClose, onUpdateAvatar }) {
  const avatarRef = React.useRef();

  function handleSubmit(event) {
    event.preventDefault();
    onUpdateAvatar({
      avatar: avatarRef.current.value,
    });
  }

  // Сброс инпута
  React.useEffect(() => {
    avatarRef.current.value = "";
  }, [isOpen]);

  return (
    <PopupWithForm
      name="edit_avatar"
      title="Обновить аватар"
      buttonText="Сохранить"
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
    >
      <label className="form__field">
        <input
          id="avatar"
          name="link"
          className="popup__input popup__input_type_link"
          type="url"
          placeholder="Ссылка на картинку"
          ref={avatarRef}
          required
        />
        <span className="popup__form-error avatar-error"></span>
      </label>
    </PopupWithForm>
  );
}

export default EditAvatarPopup;
