-- Tạo tài khoản và database cho hệ thống IDS (chạy bằng tài khoản postgres).
-- psql -U postgres -h localhost -f scripts/setup_db.sql
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ids_app') THEN
    CREATE ROLE ids_app LOGIN PASSWORD 'ids_app_dev';
  END IF;
END $$;
SELECT 'CREATE DATABASE ids OWNER ids_app ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ids')\gexec
SELECT 'CREATE DATABASE ids_test OWNER ids_app ENCODING ''UTF8'''
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ids_test')\gexec
