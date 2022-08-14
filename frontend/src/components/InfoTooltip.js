import React from "react";
import successRegistr from "../images/successful-registr.png";
import errorRegistr from "../images/registration-error.png";

function InfoTooltip(props) {
  return (
    <div className={`popup ${props.isOpen && "popup_opened"}`}>
      <div className="popup__container">
        <img
          className="popup__icon"
          src={props.isSuccessfulReg ? successRegistr : errorRegistr}
          alt={
            props.isSuccessfulReg ? 'Иконка - "Успешно"' : 'Иконка - "Ошибка"'
          }
        />
        <p className="popup__message">
          {props.isSuccessfulReg
            ? "Вы успешно зарегистрировались!"
            : "Что-то пошло не так! Попробуйте ещё раз!"}
        </p>
        <button
          onClick={props.onClose}
          className="popup__close-button"
          type="button"
          aria-label="Закрыть"
        ></button>
      </div>
    </div>
  );
}

export default InfoTooltip;
