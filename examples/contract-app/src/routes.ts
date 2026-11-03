// A second app that implements the verify target contract (docs/verify-target-contract.md) with its own tables and handler layout (DR-0016 decision 4).
import { createAuth } from "@kalahroudi/bulkhead-auth";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { parseClassification, sealedCheck } from "@kalahroudi/bulkhead-core/crypto";
import classificationFile from "../bulkhead.classification.json" with { type: "json" };
import { areaRoutes } from "./areas.ts";
import { memoRoutes } from "./memos.ts";
import { vaultRoutes } from "./vault.ts";

/** `bootstrapToken` is read per request from the Worker's env (see index.ts); undefined disables first-owner bootstrap. */
export function createContractApp(bootstrapToken: () => string | undefined = () => undefined) {
  const auth = createAuth({ bootstrapToken });
  const app = createApp({
    classification: parseClassification(classificationFile),
    schema: [
      ...auth.schema,
      `create table memos (id integer primary key autoincrement, body text not null ${sealedCheck("body")})`,
      `create table vault_entries (id text primary key, label text not null, payload text not null ${sealedCheck("payload")}, stored_at integer not null)`,
    ],
    authenticate: auth.authenticate,
  });
  auth.registerRoutes(app);
  memoRoutes(app);
  vaultRoutes(app);
  areaRoutes(app);
  return app;
}
