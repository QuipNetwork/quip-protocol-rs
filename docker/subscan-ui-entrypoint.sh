#!/bin/sh
set -eu

# next-runtime-env reads this browser-side file. Regenerate it at startup so
# one image can target any host-visible Subscan API without retaining the
# upstream Asset Hub default.
node -e 'const fs = require("fs"); const value = process.env.NEXT_PUBLIC_API_HOST || ""; fs.writeFileSync("/app/public/__ENV.js", `window.__ENV = ${JSON.stringify({ NEXT_PUBLIC_API_HOST: value })};\n`);'

exec node server.js
