const request = require('supertest');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { MongoMemoryServer } = require('mongodb-memory-server');

process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret';
process.env.MAIL_FROM = process.env.MAIL_FROM || 'test@example.com';
process.env.SMTP_PASS = process.env.SMTP_PASS || 'fake-sendgrid-key';

jest.mock('@sendgrid/mail', () => ({
  setApiKey: jest.fn(),
  send: jest.fn().mockResolvedValue([{ statusCode: 202 }]),
}));

const sgMail = require('@sendgrid/mail');
const app = require('../server');
const User = require('../models/User');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function signTestJwt(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      login: user.login,
      email: user.email,
    },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

async function createUser(overrides = {}) {
  const base = {
    firstName: 'Jane',
    lastName: 'Doe',
    login: 'janedoe',
    email: 'jane@example.com',
    passwordHash: await bcrypt.hash('Password123!', 12),
    isVerified: true,
    verifyTokenHash: null,
    verifyTokenExpiresAt: null,
    resetTokenHash: null,
    resetTokenExpiresAt: null,
    loginCodeHash: null,
    loginCodeExpiresAt: null,
    loginCodeAttempts: 0,
  };

  return User.create({ ...base, ...overrides });
}

describe('Auth endpoints', () => {
  let mongoServer;

  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create();
    const uri = mongoServer.getUri();
    await mongoose.connect(uri);
  });

  afterEach(async () => {
    jest.clearAllMocks();

    const collections = mongoose.connection.collections;
    for (const key of Object.keys(collections)) {
      await collections[key].deleteMany({});
    }
  });

  afterAll(async () => {
    await mongoose.disconnect();
    await mongoServer.stop();
  });

  describe('POST /api/register', () => {
    test('registers a new user', async () => {
      const res = await request(app).post('/api/register').send({
        firstName: 'Jane',
        lastName: 'Doe',
        login: 'janedoe',
        email: 'Jane@Example.com',
        password: 'Password123!',
      });

      expect(res.statusCode).toBe(201);
      expect(res.body.message).toMatch(/registration successful/i);

      const user = await User.findOne({ login: 'janedoe' });
      expect(user).not.toBeNull();
      expect(user.email).toBe('jane@example.com');
      expect(user.isVerified).toBe(false);
      expect(user.passwordHash).not.toBe('Password123!');
      expect(user.verifyTokenHash).toBeTruthy();
      expect(sgMail.send).toHaveBeenCalledTimes(1);
    });

    test('returns 400 when fields are missing', async () => {
      const res = await request(app).post('/api/register').send({
        firstName: 'Jane',
        email: 'jane@example.com',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/fill out all fields/i);
    });

    test('returns 400 when login already exists', async () => {
      await createUser({ login: 'janedoe', email: 'existing@example.com' });

      const res = await request(app).post('/api/register').send({
        firstName: 'Jane',
        lastName: 'Doe',
        login: 'janedoe',
        email: 'new@example.com',
        password: 'Password123!',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/exists already/i);
    });
  });

  describe('POST /api/login', () => {
    test('sends login code for verified user with correct password', async () => {
      await createUser({
        login: 'janedoe',
        email: 'jane@example.com',
        isVerified: true,
      });

      const res = await request(app).post('/api/login').send({
        login: 'janedoe',
        password: 'Password123!',
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/login code sent/i);

      const user = await User.findOne({ login: 'janedoe' });
      expect(user.loginCodeHash).toBeTruthy();
      expect(user.loginCodeExpiresAt).toBeTruthy();
      expect(user.loginCodeAttempts).toBe(0);
      expect(sgMail.send).toHaveBeenCalledTimes(1);
    });

    test('returns 400 when login or password is missing', async () => {
      const res = await request(app).post('/api/login').send({
        login: 'janedoe',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/fill out all fields/i);
    });

    test('returns 401 for invalid user', async () => {
      const res = await request(app).post('/api/login').send({
        login: 'missinguser',
        password: 'Password123!',
      });

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toMatch(/invalid user/i);
    });

    test('returns 401 for invalid password', async () => {
      await createUser({
        login: 'janedoe',
        isVerified: true,
      });

      const res = await request(app).post('/api/login').send({
        login: 'janedoe',
        password: 'WrongPassword!',
      });

      expect(res.statusCode).toBe(401);
      expect(res.body.error).toMatch(/invalid password/i);
    });

    test('returns 403 when email is not verified', async () => {
      await createUser({
        login: 'janedoe',
        isVerified: false,
      });

      const res = await request(app).post('/api/login').send({
        login: 'janedoe',
        password: 'Password123!',
      });

      expect(res.statusCode).toBe(403);
      expect(res.body.error).toMatch(/not verified/i);
    });
  });

  describe('POST /api/verify-login-code', () => {
    test('returns token for valid code', async () => {
      const rawCode = '123456';
      const user = await createUser({
        login: 'janedoe',
        loginCodeHash: hashToken(rawCode),
        loginCodeExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
        loginCodeAttempts: 0,
      });

      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
        code: rawCode,
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/login successful/i);
      expect(res.body.token).toBeTruthy();
      expect(res.body.user.login).toBe('janedoe');

      const updated = await User.findById(user._id);
      expect(updated.loginCodeHash).toBeNull();
      expect(updated.loginCodeExpiresAt).toBeNull();
      expect(updated.loginCodeAttempts).toBe(0);
    });

    test('returns 400 when login or code is missing', async () => {
      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/login and code are required/i);
    });

    test('returns 400 when no user exists', async () => {
      const res = await request(app).post('/api/verify-login-code').send({
        login: 'missinguser',
        code: '123456',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/invalid or expired code/i);
    });

    test('returns 400 when there is no active login code', async () => {
      await createUser({
        login: 'janedoe',
        loginCodeHash: null,
        loginCodeExpiresAt: null,
      });

      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
        code: '123456',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/no active login code/i);
    });

    test('returns 400 for expired code and clears it', async () => {
      const user = await createUser({
        login: 'janedoe',
        loginCodeHash: hashToken('123456'),
        loginCodeExpiresAt: new Date(Date.now() - 60 * 1000),
        loginCodeAttempts: 0,
      });

      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
        code: '123456',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/invalid or expired code/i);

      const updated = await User.findById(user._id);
      expect(updated.loginCodeHash).toBeNull();
      expect(updated.loginCodeExpiresAt).toBeNull();
      expect(updated.loginCodeAttempts).toBe(0);
    });

    test('returns 429 when too many attempts have already happened', async () => {
      await createUser({
        login: 'janedoe',
        loginCodeHash: hashToken('123456'),
        loginCodeExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
        loginCodeAttempts: 5,
      });

      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
        code: '123456',
      });

      expect(res.statusCode).toBe(429);
      expect(res.body.error).toMatch(/too many incorrect login attempts/i);
    });

    test('increments attempts on wrong code', async () => {
      const user = await createUser({
        login: 'janedoe',
        loginCodeHash: hashToken('123456'),
        loginCodeExpiresAt: new Date(Date.now() + 10 * 60 * 1000),
        loginCodeAttempts: 0,
      });

      const res = await request(app).post('/api/verify-login-code').send({
        login: 'janedoe',
        code: '654321',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/invalid or expired code/i);

      const updated = await User.findById(user._id);
      expect(updated.loginCodeAttempts).toBe(1);
      expect(updated.loginCodeHash).toBeTruthy();
    });
  });

  describe('GET /api/verify-email', () => {
    test('verifies a user with a valid token', async () => {
      const rawToken = 'verify-token-123';
      const user = await createUser({
        login: 'janedoe',
        isVerified: false,
        verifyTokenHash: hashToken(rawToken),
        verifyTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
      });

      const res = await request(app).get(`/api/verify-email?token=${rawToken}`);

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/email successfully verified/i);

      const updated = await User.findById(user._id);
      expect(updated.isVerified).toBe(true);
      expect(updated.verifyTokenHash).toBeNull();
      expect(updated.verifyTokenExpiresAt).toBeNull();
    });

    test('returns 400 when token is missing', async () => {
      const res = await request(app).get('/api/verify-email');

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/token is missing/i);
    });

    test('returns 400 when token is invalid or expired', async () => {
      const res = await request(app).get('/api/verify-email?token=bad-token');

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/invalid or expired/i);
    });
  });

  describe('POST /api/forgot-password', () => {
    test('returns generic success and stores reset token for matching user', async () => {
      const user = await createUser({
        login: 'janedoe',
        email: 'jane@example.com',
      });

      const res = await request(app).post('/api/forgot-password').send({
        login: 'janedoe',
        email: 'jane@example.com',
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/if an account exists/i);

      const updated = await User.findById(user._id);
      expect(updated.resetTokenHash).toBeTruthy();
      expect(updated.resetTokenExpiresAt).toBeTruthy();
      expect(sgMail.send).toHaveBeenCalledTimes(1);
    });

    test('returns 400 when login or email is missing', async () => {
      const res = await request(app).post('/api/forgot-password').send({
        login: 'janedoe',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/login and email are required/i);
    });

    test('returns generic success when user does not exist', async () => {
      const res = await request(app).post('/api/forgot-password').send({
        login: 'missinguser',
        email: 'missing@example.com',
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/if an account exists/i);
      expect(sgMail.send).not.toHaveBeenCalled();
    });
  });

  describe('POST /api/reset-password', () => {
    test('resets password with valid token', async () => {
      const rawToken = 'reset-token-123';
      const oldHash = await bcrypt.hash('OldPassword123!', 12);

      const user = await createUser({
        login: 'janedoe',
        passwordHash: oldHash,
        resetTokenHash: hashToken(rawToken),
        resetTokenExpiresAt: new Date(Date.now() + 30 * 60 * 1000),
      });

      const res = await request(app).post('/api/reset-password').send({
        token: rawToken,
        newPassword: 'NewPassword123!',
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.message).toMatch(/password reset was successful/i);

      const updated = await User.findById(user._id);
      expect(updated.resetTokenHash).toBeNull();
      expect(updated.resetTokenExpiresAt).toBeNull();

      const matches = await bcrypt.compare('NewPassword123!', updated.passwordHash);
      expect(matches).toBe(true);
    });

    test('returns 400 when token or newPassword is missing', async () => {
      const res = await request(app).post('/api/reset-password').send({
        token: 'abc123',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/code is invalid or expired/i);
    });

    test('returns 400 for invalid or expired token', async () => {
      const res = await request(app).post('/api/reset-password').send({
        token: 'bad-token',
        newPassword: 'NewPassword123!',
      });

      expect(res.statusCode).toBe(400);
      expect(res.body.error).toMatch(/invalid or expired/i);
    });
  });
});