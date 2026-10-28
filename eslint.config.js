import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      "*.config.mjs",
      "vestige-data/**",
      "eslint.config.js",
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // TypeScript's compiler owns undefined-global checking; no-undef is a
      // known false-positive source in TS codebases.
      "no-undef": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          ignoreRestSiblings: true,
          caughtErrors: "none",
        },
      ],
      "@typescript-eslint/consistent-type-imports": [
        "warn",
        { fixStyle: "inline-type-imports" },
      ],
      "no-constant-condition": ["error", { checkLoops: false }],
    },
  },
);
