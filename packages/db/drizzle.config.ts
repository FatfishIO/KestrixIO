/**
 * Drizzle Kit Configuration for Kestrix Database Package
 */
export default {
  schema: './packages/db/schema.ts',
  out: './packages/db/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || 'postgresql://kestrix:kestrix_dev_password@localhost:5432/kestrix',
  },
};
