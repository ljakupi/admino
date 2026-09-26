-- 0006_email_outbox.sql
-- Transactional email outbox (GH-148).
-- Request handlers queue one row per email through
-- admino.email_outbox.enqueue_email(); a background sender delivers due rows
-- over SMTP with retries and backoff, so a mail server outage never breaks a
-- request. The recipient address and language are copied from the users row
-- when the row is queued.
--
-- CHECK constraints mirror the Python bounds: the template catalog
-- (EmailTemplate), the languages (EmailLanguage), the states (OutboxStatus)
-- and the users_email_format_check address rule, so the schema stays safe
-- even against a direct-DB write that bypasses the app.
--
-- No content: a row holds the template key, the language and the template's
-- params (an org display name, links and dates), never a subject, body or
-- error text. SMTP errors echo addresses, so there is no column to keep them.
-- One-time links don't outlive delivery: a sent or failed row must hold empty
-- params, which the sender sets as it finishes the row.

CREATE TABLE email_outbox (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- CASCADE: purging a user removes their queued mail and the address in it.
    recipient_user_id UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    recipient_address TEXT        NOT NULL
        CHECK (char_length(recipient_address) BETWEEN 3 AND 254),
    template_key      TEXT        NOT NULL,
    language          TEXT        NOT NULL CHECK (language IN ('de', 'fr', 'en')),
    params            JSONB       NOT NULL DEFAULT '{}',
    status            TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sent', 'failed')),
    -- Counted when a sender claims the row; the sender stops at 10 attempts.
    attempts          INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- When the row is due next: the backoff after a failure, or the lease of
    -- the attempt in progress.
    next_attempt_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at       TIMESTAMPTZ,
    -- The same rule as users_email_format_check: no whitespace, and an '@'
    -- after a local part.
    CONSTRAINT email_outbox_address_format_check
        CHECK (recipient_address !~ '[[:space:]]' AND position('@' in recipient_address) > 1),
    -- The template catalog (EmailTemplate). Named so a later migration can
    -- replace it when the catalog grows.
    CONSTRAINT email_outbox_template_key_check CHECK (template_key IN (
        'invitation', 'password_reset', 'account_activated', 'account_deactivated',
        'budget_alert', 'model_deprecation', 'org_deletion_scheduled'
    )),
    CONSTRAINT email_outbox_params_object_check CHECK (jsonb_typeof(params) = 'object'),
    -- A row is pending exactly while it is unfinished.
    CONSTRAINT email_outbox_pending_unfinished_check
        CHECK ((status = 'pending') = (finished_at IS NULL)),
    -- Only a pending row may keep params (and the one-time links in them).
    CONSTRAINT email_outbox_finished_params_check
        CHECK (status = 'pending' OR params = '{}'::jsonb)
);

-- The sender's scan for due rows.
CREATE INDEX email_outbox_due_idx ON email_outbox (next_attempt_at) WHERE status = 'pending';
-- The retention purge's range scan over finished rows.
CREATE INDEX email_outbox_finished_at_idx ON email_outbox (finished_at);
-- The users foreign key cascade.
CREATE INDEX email_outbox_recipient_user_id_idx ON email_outbox (recipient_user_id);
