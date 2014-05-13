function SignatureError (code, error) {
    Error.call(this, error.message);
    this.name = "SignatureError";
    this.message = error.message;
    this.code = code;
    this.status = 401;
    this.inner = error;
}

SignatureError.prototype = Object.create(Error.prototype);
SignatureError.prototype.constructor = SignatureError;

module.exports = SignatureError;
