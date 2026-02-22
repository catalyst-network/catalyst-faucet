const js = require("@eslint/js");
const tseslint = require("typescript-eslint");

module.exports = tseslint.config(
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "prisma/migrations/**",
      "eslint.config.js",
      "prettier.config.cjs"
    ]
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.eslint.json"],
        tsconfigRootDir: __dirname
      }
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { "argsIgnorePattern": "^_", "varsIgnorePattern": "^_" }
      ],
      "@typescript-eslint/no-explicit-any": "off"
    }
  }
);

