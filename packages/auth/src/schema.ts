/**
 * Per-tenant tables (TENANT-3): they live in the tenant's own Durable Object database, never in the control plane.
 * Steps are applied in order and tracked by index, so they are append-only. Pass `[...authSchema, ...yourSchema]`.
 */
export const authSchema: readonly string[] = [
  `create table users (
     id text primary key,
     email text not null unique,
     password_hash text not null,
     role text not null check (role in ('member','admin','owner')),
     disabled integer not null default 0,
     created_at integer not null
   )`,
  // Only the SHA-256 of the token is stored (AUTH-4 for keys, and the same discipline for sessions).
  `create table sessions (
     token_hash text primary key,
     user_id text not null references users(id),
     created_at integer not null,
     last_seen integer not null,
     expires_at integer not null
   )`,
  `create index sessions_user on sessions (user_id)`,
  `create table api_keys (
     id text primary key,
     secret_hash text not null,
     name text not null,
     role text not null check (role in ('member','admin','owner')),
     permissions text not null,
     created_by text not null references users(id),
     created_at integer not null,
     expires_at integer,
     revoked_at integer
   )`,
  `create table login_attempts (email text not null, at integer not null)`,
  `create index login_attempts_email on login_attempts (email, at)`,
];
