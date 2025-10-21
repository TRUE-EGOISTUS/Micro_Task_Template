const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });

// Middleware
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    req.requestId = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    logger.info({ requestId: req.requestId, method: req.method, url: req.url }, `Users: Request received for ${req.method} ${req.url}`);
    next();
});
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Users: Missing or invalid Authorization header for ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: { code: 'UNAUTHORIZED', message: `Authorization header missing or invalid for ${req.method} ${req.path}` }
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        logger.info({ requestId: req.requestId, userId: decoded.id, path: req.path }, `Users: JWT verified for ${req.method} ${req.path}, userId: ${decoded.id}`);
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message, path: req.path }, `Users: Invalid token for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: `Invalid or expired token for ${req.method} ${req.path}` }
        });
    }
};
// Имитация базы данных в памяти (LocalStorage)
let fakeUsersDb = {};

const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    name: Joi.string().allow('').optional(),
    roles: Joi.array().items(Joi.string().valid('user', 'admin')).default(['user'])
});
const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const profileSchema = Joi.object({
    email: Joi.string().email().optional(),
    password: Joi.string().min(6).optional(),
    name: Joi.string().optional(),
    roles: Joi.array().items(Joi.string().valid('user', 'admin')).optional()
});
// Routes
app.post('/v1/users/register', async (req, res) => {
    try {
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            logger.warn({ requestId: req.requestId, error: error.details, path: req.path }, `Users: Validation failed for ${req.method} ${req.path}`);
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: `${error.details[0].message} for ${req.method} ${req.path}` }
            });
        }

        if (Object.values(fakeUsersDb).some(user => user.email === value.email)) {
            logger.warn({ requestId: req.requestId, path: req.path }, `Users: Email already exists for ${req.method} ${req.path}`);
            return res.status(400).json({
                success: false,
                error: { code: 'EMAIL_EXISTS', message: `Email already exists for ${req.method} ${req.path}` }
            });
        }

        const userId = uuidv4();
        const hashedPassword = await bcrypt.hash(value.password, 10);
        const now = new Date().toISOString();
        const newUser = {
            id: userId,
            email: value.email,
            password: hashedPassword,
            name: value.name || '',
            roles: value.roles,
            role: value.roles[0] || 'user',
            createdAt: now,
            updatedAt: now
        };

        fakeUsersDb[userId] = newUser;

        const token = jwt.sign({ id: userId, roles: value.roles }, JWT_SECRET, { expiresIn: '1h' });
        logger.info({ requestId: req.requestId, userId, path: req.path }, `Users: User registered successfully for ${req.method} ${req.path}, userId: ${userId}`);
        res.status(201).json({
            success: true,
            data: {
                id: userId,
                email: value.email,
                role: value.roles[0],
                name: value.name || '',
                roles: value.roles,
                createdAt: now,
                updatedAt: now,
                token
            }
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message, path: req.path }, `Users: Server error for ${req.method} ${req.path}`);
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: `Server error for ${req.method} ${req.path}` }
        });
    }
});

app.post('/v1/users/login', async (req, res) => {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId, error: error.details, path: req.path }, `Users: Validation failed for ${req.method} ${req.path}`);
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: `${error.details[0].message} for ${req.method} ${req.path}` }
        });
    }

    const user = Object.values(fakeUsersDb).find(u => u.email === value.email);
    if (!user || !(await bcrypt.compare(value.password, user.password))) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Users: Invalid credentials for ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: { code: 'INVALID_CREDENTIALS', message: `Invalid email or password for ${req.method} ${req.path}` }
        });
    }

    const token = jwt.sign({ id: user.id, roles: user.roles }, JWT_SECRET, { expiresIn: '1h' });
    logger.info({ requestId: req.requestId, userId: user.id, path: req.path }, `Users: User logged in successfully for ${req.method} ${req.path}, userId: ${user.id}`);
    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            role: user.roles[0],
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
            token
        }
    });
});
app.get('/v1/users/profile', authenticateJWT, (req, res) => {
    const user = fakeUsersDb[req.user.id];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'User not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'User not found' }
        });
    }

    logger.info({ requestId: req.requestId, userId: req.user.id }, 'User profile fetched');
    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            role: user.roles[0], // Для совместимости
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }
    });
});

app.put('/v1/users/profile', authenticateJWT, async (req, res) => {
    const user = fakeUsersDb[req.user.id];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'User not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'User not found' }
        });
    }

    const { error, value } = profileSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId }, 'Validation error');
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
        });
    }

    if (value.email) user.email = value.email;
    if (value.password) user.password = await bcrypt.hash(value.password, 10);
    if (value.name !== undefined) user.name = value.name;
    if (value.roles) {
        user.roles = value.roles;
        user.role = value.roles[0] || 'user'; // Для совместимости
    }
    user.updatedAt = new Date().toISOString();

    fakeUsersDb[req.user.id] = user;
    logger.info({ requestId: req.requestId, userId: req.user.id }, 'User profile updated');
    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            role: user.roles[0],
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }
    });
});
app.get('/v1/users', authenticateJWT, (req, res) => {
    if (!req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Users: Unauthorized access to users list for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    logger.info({ requestId: req.requestId, path: req.path }, `Users: Users list fetched successfully for ${req.method} ${req.path}`);
    res.json({
        success: true,
        data: Object.values(fakeUsersDb)
    });
});

app.get('/v1/users/:userId', authenticateJWT, (req, res) => {
    const userId = req.params.userId;
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Users: Unauthorized user access for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId, path: req.path }, `Users: User not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `User not found for ${req.method} ${req.path}` }
        });
    }

    logger.info({ requestId: req.requestId, userId, path: req.path }, `Users: User fetched successfully for ${req.method} ${req.path}, userId: ${userId}`);
    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            role: user.roles[0],
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }
    });
});


app.put('/v1/users/:userId', authenticateJWT, async (req, res) => {
    const userId = req.params.userId;
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Users: Unauthorized user update for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId, path: req.path }, `Users: User not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `User not found for ${req.method} ${req.path}` }
        });
    }

    const { error, value } = profileSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Users: Validation error for ${req.method} ${req.path}`);
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: `${error.details[0].message} for ${req.method} ${req.path}` }
        });
    }

    if (value.email) user.email = value.email;
    if (value.password) user.password = await bcrypt.hash(value.password, 10);
    if (value.name !== undefined) user.name = value.name;
    if (value.roles) {
        user.roles = value.roles;
        user.role = value.roles[0] || 'user';
    }
    user.updatedAt = new Date().toISOString();

    fakeUsersDb[userId] = user;
    logger.info({ requestId: req.requestId, userId, path: req.path }, `Users: User updated successfully for ${req.method} ${req.path}, userId: ${userId}`);
    res.json({
        success: true,
        data: {
            id: user.id,
            email: user.email,
            role: user.roles[0],
            name: user.name,
            roles: user.roles,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        }
    });
});

app.delete('/v1/users/:userId', authenticateJWT, (req, res) => {
    const userId = req.params.userId;
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Users: Unauthorized user deletion for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId, path: req.path }, `Users: User not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `User not found for ${req.method} ${req.path}` }
        });
    }

    delete fakeUsersDb[userId];
    logger.info({ requestId: req.requestId, userId, path: req.path }, `Users: User deleted successfully for ${req.method} ${req.path}, userId: ${userId}`);
    res.json({
        success: true,
        data: { message: 'User deleted' }
    });
});
app.get('/v1/users/health', (req, res) => {
    logger.info({ requestId: req.requestId, path: req.path }, `Users: Health check performed for ${req.method} ${req.path}`);
    res.json({
        success: true,
        data: { status: 'OK', service: 'Users Service', timestamp: new Date().toISOString() }
    });
});

app.get('/v1/users/status', (req, res) => {
    logger.info({ requestId: req.requestId, path: req.path }, `Users: Status check performed for ${req.method} ${req.path}`);
    res.json({ success: true, data: { status: 'Users service is running' } });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Users service running on port ${PORT}`);
});