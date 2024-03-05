import { defineConfig } from '@docplanner/remotejs';

export default defineConfig(() => ({
  name: 'header',
  moduleFederationConfig: {
    exposes: {
      './app': './src/index',
    },
  },
}));
