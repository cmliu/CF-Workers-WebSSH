import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    coverage: {
      reporter: ['text', 'html'],
      include: ['src/ssh/**/*.ts', 'src/backend/security.ts', 'src/types.ts'],
    },
  },
});
