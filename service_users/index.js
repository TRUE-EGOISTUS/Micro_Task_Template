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
    logger.info({ requestId: req.requestId, method: req.method, url: req.url }, 'Request received');
    next();
});
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn({ requestId: req.requestId }, 'Missing or invalid Authorization header');
        return res.status(401).json({
            success: false,
            error: { code: 'UNAUTHORIZED', message: 'Authorization header missing or invalid' }
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Добавляем id и role
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Invalid token');
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
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
            logger.warn({ requestId: req.requestId, error: error.details }, 'Validation failed');
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
            });
        }

        // Проверка уникальности email
        if (Object.values(fakeUsersDb).some(user => user.email === value.email)) {
            return res.status(400).json({
                success: false,
                error: { code: 'EMAIL_EXISTS', message: 'Email already exists' }
            });
        }

        // Генерация UUID вместо числа
        const userId = uuidv4();
        const hashedPassword = await bcrypt.hash(value.password, 10);
        const now = new Date().toISOString();
        const newUser = {
            id: userId,
            email: value.email,
            password: hashedPassword,
            name: value.name || '', // Пустая строка по умолчанию
            roles: value.roles, // Массив ['user'] или другой
            role: value.roles[0] || 'user', // Для обратной совместимости
            createdAt: now,
            updatedAt: now
        };

        fakeUsersDb[userId] = newUser;

        // JWT с roles (массив)
        const token = jwt.sign({ id: userId, roles: value.roles }, JWT_SECRET, { expiresIn: '1h' });
        logger.info({ requestId: req.requestId, userId }, 'User registered');
        res.status(201).json({
            success: true,
            data: {
                id: userId,
                email: value.email,
                role: value.roles[0], // Для совместимости
                name: value.name || '',
                roles: value.roles,
                createdAt: now,
                updatedAt: now,
                token
            }
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Server error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Server error' }
        });
    }
});

app.post('/v1/users/login', async (req, res) => {
    try {
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            logger.warn({ requestId: req.requestId, error: error.details }, 'Validation failed');
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
            });
        }

        const user = Object.values(fakeUsersDb).find(u => u.email === value.email);
        if (!user || !(await bcrypt.compare(value.password, user.password))) {
            logger.warn({ requestId: req.requestId }, 'Invalid credentials');
            return res.status(401).json({
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' }
            });
        }

        const token = jwt.sign({ id: user.id, roles: user.roles }, JWT_SECRET, { expiresIn: '1h' });
        logger.info({ requestId: req.requestId, userId: user.id }, 'User logged in');
        res.json({
            success: true,
            data: {
                id: user.id,
                email: user.email,
                role: user.roles[0], // Для совместимости
                name: user.name,
                roles: user.roles,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt,
                token
            }
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Server error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Server error' }
        });
    }
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
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Admin access required');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Admin access required' }
        });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const roleFilter = req.query.role; // Фильтр по роли

    let users = Object.values(fakeUsersDb);
    if (roleFilter) {
        users = users.filter(user => user.roles.includes(roleFilter));
    }

    const total = users.length;
    users = users.slice((page - 1) * limit, page * limit);

    logger.info({ requestId: req.requestId }, 'Users list fetched');
    res.json({
        success: true,
        data: {
            users: users.map(user => ({
                id: user.id,
                email: user.email,
                role: user.roles[0], // Для совместимости
                name: user.name,
                roles: user.roles,
                createdAt: user.createdAt,
                updatedAt: user.updatedAt
            })),
            page,
            limit,
            total
        }
    });
});

app.get('/v1/users/:userId', authenticateJWT, (req, res) => {
    const userId = req.params.userId; // ID уже строка (UUID)
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized access to user');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId }, 'User not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'User not found' }
        });
    }

    logger.info({ requestId: req.requestId, userId }, 'User fetched');
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


app.put('/v1/users/:userId', authenticateJWT, async (req, res) => {
    const userId = req.params.userId;
    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized update attempt');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId }, 'User not found');
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

    fakeUsersDb[userId] = user;
    logger.info({ requestId: req.requestId, userId }, 'User updated');
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
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized delete attempt');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    const user = fakeUsersDb[userId];
    if (!user) {
        logger.warn({ requestId: req.requestId, userId }, 'User not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'User not found' }
        });
    }

    delete fakeUsersDb[userId];
    logger.info({ requestId: req.requestId, userId }, 'User deleted');
    res.json({
        success: true,
        data: { message: 'User deleted' }
    });
});
app.get('/v1/users/health', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Health check');
    res.json({
        success: true,
        data: { status: 'OK', service: 'Users Service', timestamp: new Date().toISOString() }
    });
});

app.get('/v1/users/status', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Status check');
    res.json({ success: true, data: { status: 'Users service is running' } });
});
// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Users service running on port ${PORT}`);
});