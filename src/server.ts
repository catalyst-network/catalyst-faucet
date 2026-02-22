import "dotenv/config";

import { buildApp } from "./app";
import { loadConfig } from "./config";

async function main() {
  const config = loadConfig();
  const app = await buildApp(config);

  await app.listen({ port: config.port, host: config.host });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

