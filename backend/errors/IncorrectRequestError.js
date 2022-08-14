class IncorrectRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'IncorrectRequestError';
    this.statusCode = 400;
  }
}

module.exports = IncorrectRequestError;
