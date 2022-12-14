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

  setToken(token) {
    this._headers.Authorization = `Bearer ${token}`
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

  changeLikeCardStatus(cardId, isLiked) {
    if (isLiked) {
        return this.setLike(cardId);
    } else {
        return this.deleteLike(cardId);
    }
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

const BASE_URL = "https://api.mesto2022.nomoredomains.sbs";
    const api = new Api({
        url: BASE_URL,
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem('jwt')}`,
        }
    });

export default api;
