const router = require('../router');

router.all('/private/(.*)', (ctx, next) => {
	if (ctx.session && ctx.session.isAuthenticated === true) {
		return next();
	}

	ctx.status = 403;
	console.log(`rejected unauthorized request to protected resource: ${ctx.URL.pathname}`);
});
