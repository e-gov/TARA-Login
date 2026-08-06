module.exports = {
    // env.es2021 also sets parserOptions.ecmaVersion to 2021.
    env: {
        browser: true,
        es2021: true,
    },
    // Globals loaded via script tags — not imported as modules
    globals: {
        jQuery: 'readonly',
        $: 'readonly',
        QRCode: 'readonly',
        TomSelect: 'readonly',
        webeid: 'readonly',
        formatDateTimeWithBrowserOffset: 'readonly',
        supportsSmartIdApp: 'readonly',
    },
    ignorePatterns: [
        'scripts/general/', // vendor and minified files
    ],
    // These files declare the globals above. Without this, the declaration
    // itself looks unused, because the consumers are in other files.
    overrides: [
        {
            files: ['scripts/main/supports-smart-id-app.js', 'scripts/timeconverter/timeconverter.js'],
            rules: {
                'no-unused-vars': 'off',
            },
        },
    ],
    rules: {
        'no-undef': 'error',
        'no-unused-vars': ['warn', { args: 'all', argsIgnorePattern: '^_' }],
        eqeqeq: ['warn', 'always', { null: 'ignore' }],
        'no-eval': 'error',
        'no-console': ['warn', { allow: ['error', 'warn'] }],
        curly: ['warn', 'all'],
        'no-var': 'error',
        'prefer-const': 'warn',
        'prefer-template': 'warn',
    },
};
