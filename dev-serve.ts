// Dev-only launcher (not used by the harness): serves app.ts on a fixed local port
// so the kit's conformance runner (sdk/run.ts) can drive it without the env lifecycle.
import { createApp } from './app.ts';
const port = Number(process.env.DEV_PORT ?? 8791);
const server = createApp();
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`[dev] serving on http://127.0.0.1:${port}\n`);
});
