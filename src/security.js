const { createHmac, randomBytes } = require('crypto');
const { promisify } = require('util');

const Base32 = require('hi-base32');

const randomBytesAsync = promisify(randomBytes);

const OTP_INTERVAL = 30 * 1000;
const SESSION_MAX_AGE = 6 * 60 * 60 * 1000;
const SESSION_TOKEN_COOKIE = 'session-token';

const store = new Map();

async function createSession(ctx) {
	const bytes = await randomBytesAsync(128);
	const accessToken = bytes.toString('hex');

	ctx.cookies.set(SESSION_TOKEN_COOKIE, accessToken, {
		httpOnly: true,
		maxAge: SESSION_MAX_AGE
	});

	const session = {
		accessToken,
		expiresAt: Date.now() + SESSION_MAX_AGE,
		isAuthenticated: false
	};

	store.set(accessToken, session);
	return session;
}

function destroySession(ctx) {
	if (ctx.session) {
		store.delete(ctx.session.accessToken);
		ctx.cookies.set(SESSION_TOKEN_COOKIE, '', {
			httpOnly: true,
			maxAge: 0
		});
	}
}

function verifySession(ctx, next) {
	const accessToken = ctx.cookies.get(SESSION_TOKEN_COOKIE);
	if (accessToken) {
		const session = store.get(accessToken);
		if (session) {
			if (Date.now() < session.expiresAt) {
				ctx.session = session;
			}
			else {
				store.delete(accessToken);
			}
		}
	}

	return next();
}

// 2FA
// secret: E6A5IMWFFU6YMX4W55UH6RPLJOYNQSPO

async function generateOtpSecret() {
	const bytes = await randomBytesAsync(20);
	return Base32.encode(bytes).replace(/=+$/, '');
}

function getOtpCode(secret, counter) {
	const buffer = Buffer.allocUnsafe(8);
	buffer.writeBigUInt64BE(BigInt(counter));

	const key = Buffer.from(Base32.decode.asBytes(secret));
	const hmac = createHmac('sha1', key)
		.update(buffer)
		.digest();

	const offset = hmac[hmac.length - 1] & 0xf;
	const code = 
		((hmac[offset]     & 0x7f) << 24) |
		((hmac[offset + 1] & 0xff) << 16) |
		((hmac[offset + 2] & 0xff) <<  8) |
		( hmac[offset + 3] & 0xff);

	return code
		.toString()
		.padStart(6, '0')
		.slice(-6);
}

function getOtpCounter() {
	return Math.trunc(Date.now() / OTP_INTERVAL);
}

module.exports = {
	createSession,
	destroySession,
	verifySession,
	generateOtpSecret,
	getOtpCode,
	getOtpCounter
};
