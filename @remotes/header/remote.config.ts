import { defineConfig } from '@docplanner/remotejs';

export default defineConfig(() => ({
  name: 'header',
  translations: {
    entry: './.i18n/*.json',
  },
  moduleFederationConfig: {
    exposes: {
      './app': './src/index',
    },
  },
}));
