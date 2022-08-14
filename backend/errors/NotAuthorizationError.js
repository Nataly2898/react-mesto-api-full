class NotAuthorizationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotAuthorizationError';
    this.statusCode = 401;
  }
}

module.exports = NotAuthorizationError;
