module.exports = {
  extends: ['eslint:recommended', 'plugin:prettier/recommended', 'plugin:jest/recommended'],
  env: {
    node: true,
    jest: true,
    ['jest/globals']: true,
    es2024: true,
  },
  plugins: ['prettier', 'jest'],
  parserOptions: {
    ecmaVersion: 'latest',
  },
}
