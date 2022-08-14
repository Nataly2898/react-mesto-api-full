import { useState } from "react";

const Register = ({ onRegister }) => {
  const [state, setState] = useState({
    email: "",
    password: "",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setState((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const { email, password } = state;
    if (onRegister && email && password) {
      onRegister(email, password);
    }
  };

  return (
    <div className="login login_type_auth">
      <h2 className="login__title">Регистрация</h2>
      <form className="login__form" name="reg-form" onSubmit={handleSubmit}>
        <input
          className="login__input"
          id="email"
          name="email"
          type="email"
          value={state.email}
          onChange={handleChange}
          placeholder="Email"
          required
        />

        <input
          className="login__input"
          id="password"
          name="password"
          type="password"
          value={state.password}
          onChange={handleChange}
          placeholder="Пароль"
          required
        />

        <button type="submit" onSubmit={handleSubmit} className="login__submit">
          Зарегистрироваться
        </button>
        <p className="login__text">
          Уже зарегистрированы?
          <a className="login__link" href="/react-mesto-auth/signin">
            {" "}
            Войти
          </a>
        </p>
      </form>
    </div>
  );
};

export default Register;
