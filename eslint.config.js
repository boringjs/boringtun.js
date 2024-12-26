const eslintPluginPrettierRecommended = require('eslint-plugin-prettier/recommended')
const jest = require('eslint-plugin-jest')
const js = require('@eslint/js')
const globals = require('globals')

module.exports = [
  {
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },
  },
  {
    ...js.configs.recommended,
    files: ['**/**/*.js'],
  },
  eslintPluginPrettierRecommended,
  {
    ...jest.configs['flat/recommended'],
    files: ['./tests/**/*.(test|spec).js'],
  },
]
