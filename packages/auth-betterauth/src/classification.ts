// DR-0011 spike: classification of the tables this kit adds, so an app that declares a classification (and so turns on CRYPTO-1) can run it.
// No auth field here is "sensitive" or "secret": Better Auth reads and writes these columns as plain values and cannot go through the sealed
// handle. That is a finding (see DR-0015): a session token and a password hash sit in `internal` columns, as the shipped auth's hashes do.
import type { ClassifiedField, DataClass } from "@kalahroudi/bulkhead-core/crypto";

const t = (table: string, cls: DataClass, ...fields: string[]): ClassifiedField[] => fields.map((field) => ({ table, field, class: cls }));

export const betterAuthFields: readonly ClassifiedField[] = [
  ...t("user", "internal", "id", "emailVerified", "createdAt", "updatedAt", "role", "disabled"),
  ...t("user", "personal", "name", "email", "image"),
  ...t("session", "internal", "id", "expiresAt", "token", "createdAt", "updatedAt", "userId"),
  ...t("session", "personal", "ipAddress", "userAgent"),
  ...t("account", "internal", "id", "accountId", "providerId", "userId", "accessToken", "refreshToken", "idToken", "accessTokenExpiresAt", "refreshTokenExpiresAt", "scope", "password", "createdAt", "updatedAt"),
  ...t("verification", "internal", "id", "identifier", "value", "expiresAt", "createdAt", "updatedAt"),
  ...t("api_keys", "internal", "id", "secret_hash", "name", "role", "permissions", "created_by", "created_at", "expires_at", "revoked_at"),
  ...t("login_attempts", "personal", "email"),
  ...t("login_attempts", "internal", "at"),
];
