// eslint.config.mjs
import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,

  {
    files: ["**/*.js"],

    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: {
        ...globals.node
      }
    },

    rules: {
      // Allow CommonJS
      "no-undef": "off",

      // Node projects use require/module
      "@typescript-eslint/no-require-imports": "off",

      // OWASP labs often keep unused vars intentionally
      "no-unused-vars": "warn",

      // Security labs may demonstrate bad patterns intentionally
      "no-eval": "off",
      "no-implied-eval": "off"
    }
  }
];
