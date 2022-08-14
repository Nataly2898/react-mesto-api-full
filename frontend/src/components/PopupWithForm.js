import React from "react";

function PopupWithForm(props) {
  return (
    <div
      className={`popup popup_form_${props.name} ${
        props.isOpen && "popup_opened"
      }`}
    >
      <div className="popup__container">
        <h3 className="popup__title">{props.title}</h3>
        <form
          className="form popup__form"
          name={props.name}
          noValidate
          method="post"
          onSubmit={props.onSubmit}
        >
          {props.children}
          <button className="form__submit popup__button" type="submit">
            {props.buttonText}
          </button>
        </form>
        <button
          className="popup__close-button"
          type="button"
          aria-label="Закрыть"
          onClick={props.onClose}
        ></button>
      </div>
    </div>
  );
}

export default PopupWithForm;
