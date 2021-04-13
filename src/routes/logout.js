const router = require('../router');
const { destroySession } = require('../security');

router.get('/logout', ctx => {
	destroySession(ctx);
	ctx.redirect('/');
});
