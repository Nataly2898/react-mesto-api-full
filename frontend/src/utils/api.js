
const BASE_URL = "https://api.mesto2022.nomoredomains.sbs";

class Api {
  constructor(config) {
    this._url = config.url;
    this._headers = config.headers;
  }

  _handleError(res) {
    if (res.ok) {
      return res.json();
    }
    return Promise.reject(`Ошибка: ${res.status}`);
  }

  // Получение карточек с сервера
  getInitialCards() {
    return fetch(`${this._url}/cards`, {
      headers: this._headers,
    }).then((res) => this._handleError(res));
  }

  // Добавление новой карточки через попап
  addCard(data) {
    return fetch(`${this._url}/cards`, {
      method: "POST",
      headers: this._headers,
      body: JSON.stringify({
        name: data.name,
        link: data.link,
      }),
    }).then((res) => this._handleError(res));
  }

  // Удаление карточки
  deleteCard(cardId) {
    return fetch(`${this._url}/cards/${cardId}`, {
      method: "DELETE",
      headers: this._headers,
    }).then((res) => this._handleError(res));
  }

  // Лайк карточки
  setLike(cardId) {
    return fetch(`${this._url}/cards/${cardId}/likes`, {
      method: "PUT",
      headers: this._headers,
    }).then((res) => this._handleError(res));
  }

  // Удаление лайка
  deleteLike(cardId) {
    return fetch(`${this._url}/cards/${cardId}/likes`, {
      method: "DELETE",
      headers: this._headers,
    }).then((res) => this._handleError(res));
  }

  // Получение информации о пользователе с сервера
  getUserInfo() {
    return fetch(`${this._url}/users/me`, {
      headers: this._headers,
      method: "GET",
    }).then((res) => {
      if (res.ok) {
        return res.json();
      } else {
        this._handleError(res);
      }
    });
  }

  // Редактирование информации о пользователе через попап
  setUserInfo(data) {
    return fetch(`${this._url}/users/me`, {
      method: "PATCH",
      headers: this._headers,
      body: JSON.stringify({
        name: data.name,
        about: data.about,
      }),
    }).then((res) => this._handleError(res));
  }

  // Редактирование аватара пользователя через попап
  setUserAvatar(data) {
    return fetch(`${this._url}/users/me/avatar`, {
      method: "PATCH",
      headers: this._headers,
      body: JSON.stringify({
        avatar: data.avatar,
      }),
    }).then((res) => this._handleError(res));
  }
}

/*
// Инициализация класса Api
const api = new Api({
  url: "https://mesto.nomoreparties.co/v1/cohort-41",
  headers: {
    authorization: "a3398c1a-3ea4-4c41-8ac3-48ad581650e6",
    "Content-Type": "application/json",
  },
});
*/

const api = new Api({
  url: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  }
});

export default api;
