const router = require('../router');
const { createSession } = require('../security');

router.post('/login', async ctx => {
	const { body } = ctx.request;
	console.log(`login attempt: ${JSON.stringify(body)}`);

	if (body.username === process.env.AUTH_USERNAME && body.password === process.env.AUTH_PASSWORD) {
		await createSession(ctx);
		ctx.response.status = 200;
	}
	else {
		ctx.response.status = 403;
	}
});
