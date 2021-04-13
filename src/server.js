const Path = require('path');

const Koa = require('koa');
const serveStatic = require('koa-static');
const parseBody = require('koa-bodyparser');
const { verifySession } = require('./security');

const app = new Koa();
const router = require('./router');

// register custom routes
require('./routes/private');
require('./routes/login');
require('./routes/logout');
require('./routes/otp');

// serve static files
const root = Path.join(process.cwd(), './static');
console.log(`serving static files from: ${root}`);

app.use(verifySession);
app.use(parseBody());
app.use(router.routes());
app.use(serveStatic(root));

// start the server
app.listen(8080);

