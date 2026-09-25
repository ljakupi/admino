-- 0003_remove_files_tool.sql
-- Remove the local files tool from existing installs (GH-143).
-- The files tool and its host-directory sandbox (files.allowed_paths, the
-- /app/documents mount) are gone. Fresh installs never seed files rows; this
-- cleans up the rows an existing install seeded or saved before the removal:
-- the files.* permission rules, the files settings section, and the files
-- on/off switch inside the tools settings object.

DELETE FROM permissions WHERE tool = 'files';

DELETE FROM settings WHERE key = 'files';

-- Only objects have keys; skip a corrupt non-object value instead of failing
-- the migration (startup already falls back to defaults for such values).
UPDATE settings SET value = value - 'files'
WHERE key = 'tools' AND jsonb_typeof(value) = 'object';
