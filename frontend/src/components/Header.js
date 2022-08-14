import React from "react";
import { Link, Route } from "react-router-dom";
import Logo from "../images/logo.svg";

function Header({ loggedIn, userEmail, onSignOut }) {
  return (
    <header className="header">
      <img src={Logo} alt="Логотип сайта Mesto" className="header__logo" />
      {!loggedIn ? (
        <nav>
          <Route path="/signin">
            <Link className="header__navlink" to="/signup">
              Регистрация
            </Link>
          </Route>
          <Route path="/signup">
            <Link className="header__navlink" to="/signin">
              Войти
            </Link>
          </Route>
        </nav>
      ) : (
        <div className="header__user-info">
          <p className="header__email">{userEmail}</p>
          <button onClick={onSignOut} className="header__button" type="button">
            Выход
          </button>
        </div>
      )}
    </header>
  );
}

export default Header;
