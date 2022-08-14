export const formValidators = {};

export const  popupProfileSelector = '.popup_form_edit-profile';
export const popupAddCardSelector = '.popup_form_add-card';
export const  popupAdddCardDelSelector = '.popup_form_addcard-delete';
export const popupAvatarSelector = '.popup_form-edit_avatar';

export const profileEdit = document.querySelector('.profile__edit-button');
export const profileTitleSelector = '.profile__title';
export const profileDescriptionSelector = '.profile__description';

export const avatarFormSelector = 'avatarform';
export const avatarSelector = '.profile__avatar';
export const editButtonAvatar = document.querySelector('.profile__avatar-button');
export const popupEditAvatar = document.querySelector('.popup_form_edit_avatar');
export const  popupAdddCardDel = document.querySelector('.popup_form_addcard-delete');

export const profileFormSelector = "profilform";
export const profileNameInput = document.querySelector('.popup__input_type_name');
export const profileJobInput = document.querySelector('.popup__input_type_description');
export const popupView = document.querySelector('.popup_view-image');
export const popupViewImage = popupView.querySelector('.popup__image');
export const popupViewDesc = popupView.querySelector('.popup__description');
export const addCardButton = document.querySelector('.profile__add-button');
export const popupAddCard = document.querySelector('.popup_form_add-card');
export const popupAddCardName = popupAddCard.querySelector('.popup__input_type_title');
export const popupAddCardLink = popupAddCard.querySelector('.popup__input_type_link');

export const addCardFormSelector = "cardform";

export const elementListSelector ='.cards__list';

// объект настройки валидации
export const config = {
  formSelector: '.popup__form',
  inputSelector: '.popup__input',
  submitButtonSelector: '.popup__button',
  inactiveButtonClass: 'popup__button_disabled',
  inputErrorClass: 'popup__input_type_error',
  errorClass: 'popup__error_visible'
}