module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  testTimeout: 30000,
  setupFilesAfterEnv: [],
  globals: {
    'ts-jest': {
      tsconfig: 'tsconfig.json',
    },
  },
};
