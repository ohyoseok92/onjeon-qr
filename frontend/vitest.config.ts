import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { environment: 'jsdom', include: ['src/**/*.test.tsx'], clearMocks: true, pool: 'threads', maxWorkers: 1 },
});
