// DR-0011 spike: the tables Better Auth needs, in the tenant's own Durable Object database (TENANT-3).
// Steps are append-only, like the shipped auth schema. Better Auth writes dates as ISO-8601 text (supportsDates is false in the adapter),
// so those columns are text and compare correctly as strings. "role" has no default (AUTH-1).
export const betterAuthSchema: readonly string[] = [
  `create table "user" (
     "id" text primary key,
     "name" text not null,
     "email" text not null unique,
     "emailVerified" integer not null default 0,
     "image" text,
     "createdAt" text not null,
     "updatedAt" text not null,
     "role" text not null check ("role" in ('member','admin','owner')),
     "disabled" integer not null default 0
   )`,
  `create table "session" (
     "id" text primary key,
     "expiresAt" text not null,
     "token" text not null unique,
     "createdAt" text not null,
     "updatedAt" text not null,
     "ipAddress" text,
     "userAgent" text,
     "userId" text not null references "user"("id")
   )`,
  `create index "session_user" on "session" ("userId")`,
  `create table "account" (
     "id" text primary key,
     "accountId" text not null,
     "providerId" text not null,
     "userId" text not null references "user"("id"),
     "accessToken" text,
     "refreshToken" text,
     "idToken" text,
     "accessTokenExpiresAt" text,
     "refreshTokenExpiresAt" text,
     "scope" text,
     "password" text,
     "createdAt" text not null,
     "updatedAt" text not null
   )`,
  `create index "account_user" on "account" ("userId")`,
  `create table "verification" (
     "id" text primary key,
     "identifier" text not null,
     "value" text not null,
     "expiresAt" text not null,
     "createdAt" text not null,
     "updatedAt" text not null
   )`,
];

// API keys stay ours in the spike (DR-0011 item 2g): Better Auth's key plugin is a separate package and was not evaluated here.
export const keySchema: readonly string[] = [
  `create table api_keys (
     id text primary key,
     secret_hash text not null,
     name text not null,
     role text not null check (role in ('member','admin','owner')),
     permissions text not null,
     created_by text not null references "user"("id"),
     created_at integer not null,
     expires_at integer,
     revoked_at integer
   )`,
  `create table login_attempts (email text not null, at integer not null)`,
  `create index login_attempts_email on login_attempts (email, at)`,
];
