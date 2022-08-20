import React, { useState, useEffect } from 'react';
import { Route, Switch, Redirect, useHistory } from 'react-router-dom';
import "../index.css";
import Header from "./Header.js";
import Main from "./Main.js";
import Footer from "./Footer.js";
import ImagePopup from "./ImagePopup";
import EditProfilePopup from "./EditProfilePopup";
import EditAvatarPopup from "./EditAvatarPopup";
import AddPlacePopup from "./AddPlacePopup";
import ProtectedRoute from './ProtectedRoute';
import Login from "./Login";
import Register from "./Register";
import InfoTooltip from "./InfoTooltip";
import * as auth from '../utils/auth';
import CurrentUserContext from "../contexts/CurrentUserContext";
import api from "../utils/api";

function App() {
    const [isEditAvatarPopupOpen, setIsEditAvatarPopupOpen] = useState(false);
    const [isEditProfilePopupOpen, setIsEditProfilePopupOpen] = useState(false);
    const [isAddPlacePopupOpen, setIsAddPlacePopupOpen] = useState(false);
    const [selectedCard, setSelectedCard] = useState(null);
    const [currentUser, setCurrentUser] = useState({});
    const [cards, setCards] = useState([]);
    // Авторизация пользователя
    const [loggedIn, setLoggedIn] = useState(false);
    // Email пользователя
    const [userEmail, setUserEmail] = useState("");
    // Аутентификации пользователя
    const [isSuccessfulReg, setIsSuccessfulReg] = useState(false);
    const [infoTooltipPopupOpen, setInfoTooltipPopupOpen] = useState(false);
    const history = useHistory();

    //Получение информации о пользователе
    useEffect(() => {
        if (!loggedIn) return
        api.getUserInfo()
            .then(setCurrentUser)
            .catch(console.error);
    }, [loggedIn])

    //Получение информации о карточках
    useEffect(() => {
        if (!loggedIn) return
        api.getInitialCards()
            .then(res => {
                setCards(res?.reverse());
            })
            .catch(err => console.error(err));
    }, [loggedIn]);


    function handleAddPlaceSubmit(data) {
        api.addCard(data)
            .then((newCard) => {
                setCards([newCard, ...cards]);
                closeAllPopups();
            })
            .catch((err) => {
                console.log(err);
            });
    }

    // Поддержка лайков и дизлайков
    function handleCardLike(card) {
        // Снова проверяем, есть ли уже лайк на этой карточке
        const isLiked = card.likes.some(i => i === currentUser._id);

        // Отправляем запрос в API и получаем обновлённые данные карточки
        api.changeLikeCardStatus(card._id, !isLiked)
            .then((newCard) => {
                // Формируем новый массив на основе имеющегося, подставляя в него новую карточку
                setCards((state) => state.map((c) => c._id === card._id ? newCard : c));
            })
            .catch((err) => {
                console.log(err);
            })
    }

    // Поддержка удаления карточки
    function handleCardDelete(card) {
        api.deleteCard(card._id)
            .then(() => {
                setCards(cards.filter((c) => c._id !== card._id));
            })
            .catch((err) => {
                console.log(err);
            });
    }

    // Обработчик редактирования аватара
    function handleEditAvatarClick() {
        setIsEditAvatarPopupOpen(true);
    }

    // Обработчик кнопки редактирования профиля
    function handleEditProfileClick() {
        setIsEditProfilePopupOpen(true);
    }

    // Обработчик добавления карточки
    function handleAddPlaceClick() {
        setIsAddPlacePopupOpen(true);
    }

    // Обработчик открытия карточки
    function handleCardClick(card) {
        setSelectedCard(card);
    }

    //Обработчик закрытия popup
    function closeAllPopups() {
        setIsEditAvatarPopupOpen(false);
        setIsEditProfilePopupOpen(false);
        setIsAddPlacePopupOpen(false);
        setSelectedCard(null);
        setInfoTooltipPopupOpen(false);
    }

    // Функции изменения данных пользователя
    function handleUpdateUser(data) {
        api.setUserInfo(data)
            .then((data) => {
                setCurrentUser(data);
                closeAllPopups();
            })
            .catch(console.error);
    }

    // Функции изменения данных аватара
    function handleUpdateAvatar(data) {
        api.setUserAvatar(data)
            .then((data) => {
                setCurrentUser(data);
                closeAllPopups();
            })
            .catch(console.error);
    }

    // Регистрация и Авторизация профиля
    function handleRegister(email, password) {
        auth.register(email, password)
            .then(() => {
                setUserEmail(email)
                setIsSuccessfulReg(true);
                setInfoTooltipPopupOpen(true);
                history.push('/signin');
            })
            .catch((err) => {
                setIsSuccessfulReg(false);
                setInfoTooltipPopupOpen(true);
                console.log(`Ошибка регистрации. ${err}`);
            })
    }

    function handleLogin(email, password) {
        auth.authorize(email, password)
            .then((response) => {
                if (response) {
                    localStorage.setItem('jwt', response.token);
                    api.setToken(response.token)
                    setUserEmail(email);
                    setLoggedIn(true);
                    history.push('/');
                }
            })
            .catch((err) => {
                setIsSuccessfulReg(false);
                setInfoTooltipPopupOpen(true);
                console.log(`Невозможно войти. ${err}`);
            })
    }

    // Выход
    const handleSignOut = () => {
        setLoggedIn(false);
        localStorage.removeItem('jwt');
        history.push("/signin");
    }

    // Проверка токен
    useEffect(() => {
        const handleCheckToken = () => {
            const jwt = localStorage.getItem('jwt');
            if (!jwt) {
                return;
            }
            auth.checkToken(jwt)
                .then((response) => {
                    setUserEmail(response.email);
                    setLoggedIn(true);
                    history.push('/');
                })
                .catch((err) => console.log(err));
        };

        handleCheckToken()
    }, [history]);

    return (
        <CurrentUserContext.Provider value={currentUser}>
            <div className="root">
                <div className="page">

                    <Header
                        loggedIn={loggedIn}
                        userEmail={userEmail}
                        onSignOut={handleSignOut}
                    />

                    <Switch>
                        <ProtectedRoute
                            exact path="/"
                            loggedIn={loggedIn}
                            component={Main}
                            cards={cards}
                            onEditProfile={handleEditProfileClick}
                            onAddPlace={handleAddPlaceClick}
                            onEditAvatar={handleEditAvatarClick}
                            onCardClick={handleCardClick}
                            onCardLike={handleCardLike}
                            onCardDelete={handleCardDelete}
                        />

                        <Route path="/signin">
                            <Login
                                onLogin={handleLogin}
                            />
                        </Route>

                        <Route path="/signup">
                            <Register
                                onRegister={handleRegister}
                            />
                        </Route>

                        <Route exact path="*">
                            {loggedIn ? <Redirect to="/" /> : <Redirect to="/signin" />}
                        </Route>
                    </Switch>

                    <Footer />

                    {/* Попап обновление Аватара */}
                    <EditAvatarPopup
                        isOpen={isEditAvatarPopupOpen}
                        onClose={closeAllPopups}
                        onUpdateAvatar={handleUpdateAvatar}
                    />

                    {/* Попап редактирование профиля */}
                    <EditProfilePopup
                        isOpen={isEditProfilePopupOpen}
                        onClose={closeAllPopups}
                        onUpdateUser={handleUpdateUser}
                    />

                    {/* Попап добавление Карточки */}
                    <AddPlacePopup
                        isOpen={isAddPlacePopupOpen}
                        onClose={closeAllPopups}
                        onAddPlace={handleAddPlaceSubmit}
                    />

                    {/* Попап открытия карточки */}
                    <ImagePopup
                        card={selectedCard}
                        onClose={closeAllPopups}
                    />

                    <InfoTooltip
                        isOpen={infoTooltipPopupOpen}
                        isSuccessfulReg={isSuccessfulReg}
                        onClose={closeAllPopups}
                    />

                </div>
            </div>
        </CurrentUserContext.Provider>
    );
}

export default App;
