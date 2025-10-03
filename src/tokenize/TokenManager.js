const Jwt = require('@hapi/jwt');
const InvariantError = require('../exceptions/InvariantError');

const TokenManager = {
  generateAccessToken: (payload) => Jwt.token.generate(payload, { key: process.env.ACCESS_TOKEN_KEY, algorithm: 'HS256' }),
  generateRefreshToken: (payload) => Jwt.token.generate(payload, { key: process.env.REFRESH_TOKEN_KEY, algorithm: 'HS256' }),
  verifyRefreshToken: (refreshToken) => {
    try {
      const artifacts = Jwt.token.decode(refreshToken);
      Jwt.token.verifySignature(artifacts, process.env.REFRESH_TOKEN_KEY);
      const { payload } = artifacts.decoded;
      return payload;
    } catch {
      throw new InvariantError('Refresh token tidak valid');
    }
  },

};

module.exports = TokenManager;
