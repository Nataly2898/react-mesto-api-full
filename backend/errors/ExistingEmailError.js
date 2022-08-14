class ExistingEmailError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ExistingEmailError';
    this.statusCode = 409;
  }
}

module.exports = ExistingEmailError;
