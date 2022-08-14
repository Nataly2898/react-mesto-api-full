import React from "react";

function ImagePopup({ card, onClose }) {
  return (
    <section
      className={`popup popup_view-image` + (card !== null && " popup_opened")}
    >
      <div className="popup__content">
        <img src={card?.link} alt={card?.name} className="popup__image" />
        <p className="popup__description">{card?.name}</p>
        <button
          className="popup__close-button"
          type="button"
          aria-label="Закрыть"
          onClick={onClose}
        ></button>
      </div>
    </section>
  );
}

export default ImagePopup;
