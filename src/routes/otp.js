const router = require('../router');
const { getOtpCode, getOtpCounter } = require('../security');

router.post('/otp', ctx => {
	const { body } = ctx.request;
	console.log(`2FA attempt: ${JSON.stringify(body)}`);

	if (ctx.session) {
		const secret = process.env.AUTH_SECRET;
		const counter = getOtpCounter();
		const code = getOtpCode(secret, counter);
	
		if (body.code === code) {
			ctx.session.isAuthenticated = true;
			ctx.response.status = 200;
			return;
		}
	}

	ctx.response.status = 403;
});
