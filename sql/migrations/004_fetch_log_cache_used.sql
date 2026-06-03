-- cache_used is already present in the initial schema for fresh databases.
-- This migration exists to keep user_version aligned with historical releases.

PRAGMA user_version = 4;
