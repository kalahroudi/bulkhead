// Compiles the current package to dist/ (JS + declarations). Dev exports keep pointing at src so the monorepo and the gates
// run unchanged; `publishConfig.exports` swaps in dist/ only when the package is packed.
import { spawnSync } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const cwd = process.cwd();
rmSync(join(cwd, "dist"), { recursive: true, force: true });
// The verifier also ships its fixture, so its rootDir is the package; everyone else compiles src only.
const includeFixture = existsSync(join(cwd, "fixture"));
const config = join(cwd, "tsconfig.build.json");
writeFileSync(config, JSON.stringify({
  extends: "../../tsconfig.base.json",
  compilerOptions: {
    noEmit: false, outDir: "dist", rootDir: includeFixture ? "." : "src", declaration: true,
    allowImportingTsExtensions: false, rewriteRelativeImportExtensions: true, sourceMap: false,
  },
  include: includeFixture ? ["src", "fixture"] : ["src"],
}, null, 2));
try {
  const r = spawnSync(join(import.meta.dirname, "../node_modules/.bin/tsc"), ["-p", config], { stdio: "inherit" });
  process.exitCode = r.status ?? 1;
} finally {
  rmSync(config, { force: true });
}
