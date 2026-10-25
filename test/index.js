// Node 22 on Windows resolves an explicit test/ argument as a module directory.
// This bridge keeps `node --test test/` portable without flags or dependencies.
require('./scar-tissue.test.mjs');
