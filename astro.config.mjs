// astro.config.mjs
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';

export default defineConfig({
  integrations: [mdx()],
  // This is the key part for content collections:
  collections: {
    'writeups': {
      type: 'content',
      // schema is defined in src/content/config.ts
    },
  },
});