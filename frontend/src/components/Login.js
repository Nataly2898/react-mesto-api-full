import { useState } from "react";

const Login = ({ onLogin }) => {
  const [inputs, setInputs] = useState({
    email: "",
    password: "",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setInputs((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const { email, password } = inputs;
    if (onLogin && email && password) {
      onLogin(email, password);
    }
  };

  return (
    <div className="login login_type_auth">
      <h2 className="login__title">Вход</h2>
      <form className="login__form" name="log-form" onSubmit={handleSubmit}>
        <input
          type="email"
          className="login__input"
          placeholder="Email"
          name="email"
          value={inputs.email}
          onChange={handleChange}
          required
        />

        <input
          type="password"
          className="login__input"
          placeholder="Пароль"
          name="password"
          value={inputs.password}
          onChange={handleChange}
          required
        />

        <button type="submit" className="login__submit">
          Войти
        </button>
      </form>
    </div>
  );
};

export default Login;
