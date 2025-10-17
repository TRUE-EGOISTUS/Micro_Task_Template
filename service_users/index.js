const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });

// Middleware
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    req.requestId = Date.now().toString();
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
let currentId = 1;

const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid('user', 'admin').default('user')
});
const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

const profileSchema = Joi.object({
    email: Joi.string().email().optional(),
    password: Joi.string().min(6).optional()
});
// Routes
app.post('/v1/users/register', async (req, res) => {
    try {
        // Валидация
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
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

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(value.password, 10);
        const userId = currentId++;
        const newUser = {
            id: userId,
            email: value.email,
            password: hashedPassword,
            role: value.role
        };

        fakeUsersDb[userId] = newUser;

        // Выдача JWT
        const token = jwt.sign({ id: userId, role: value.role }, JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({
            success: true,
            data: { id: userId, email: value.email, role: value.role, token }
        });
    } catch (err) {
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
            logger.warn({ requestId: req.requestId, email: value.email }, 'Invalid credentials');
            return res.status(401).json({
                success: false,
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' }
            });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
        logger.info({ requestId: req.requestId, userId: user.id }, 'User logged in');
        res.json({
            success: true,
            data: { id: user.id, email: user.email, role: user.role, token }
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Login error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Server error' }
        });
    }
});
app.get('/v1/users/profile', authenticateJWT, (req, res) => {
    const user = fakeUsersDb[req.user.id];
    logger.info({ requestId: req.requestId, userId: req.user.id }, 'Profile fetched');
    res.json({
        success: true,
        data: { id: user.id, email: user.email, role: user.role }
    });
});

app.put('/v1/users/profile', authenticateJWT, async (req, res) => {
    try {
        const { error, value } = profileSchema.validate(req.body);
        if (error) {
            logger.warn({ requestId: req.requestId, error: error.details }, 'Validation failed');
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
            });
        }

        const user = fakeUsersDb[req.user.id];
        if (value.email) user.email = value.email;
        if (value.password) user.password = await bcrypt.hash(value.password, 10);
        fakeUsersDb[req.user.id] = user;
        logger.info({ requestId: req.requestId, userId: req.user.id }, 'Profile updated');
        res.json({
            success: true,
            data: { id: user.id, email: user.email, role: user.role }
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Profile update error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Server error' }
        });
    }
});
app.get('/v1/users', authenticateJWT, (req, res) => {
    if (req.user.role !== 'admin') {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized access to users list');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Admin access required' }
        });
    }

    const users = Object.values(fakeUsersDb).map(u => ({
        id: u.id,
        email: u.email,
        role: u.role
    }));
    logger.info({ requestId: req.requestId }, 'Users list fetched');
    res.json({ success: true, data: users });
});

app.get('/v1/users/:userId', authenticateJWT, (req, res) => {
    const userId = parseInt(req.params.userId);
    if (req.user.id !== userId && req.user.role !== 'admin') {
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
        data: { id: user.id, email: user.email, role: user.role }
    });
});

app.put('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const updates = req.body;

    if (!fakeUsersDb[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const updatedUser = {
        ...fakeUsersDb[userId],
        ...updates
    };

    fakeUsersDb[userId] = updatedUser;
    res.json(updatedUser);
});

app.delete('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);

    if (!fakeUsersDb[userId]) {
        return res.status(404).json({error: 'User not found'});
    }

    const deletedUser = fakeUsersDb[userId];
    delete fakeUsersDb[userId];

    res.json({message: 'User deleted', deletedUser});
});
app.get('/users/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Users Service',
        timestamp: new Date().toISOString()
    });
});

app.get('/users/status', (req, res) => {
    res.json({status: 'Users service is running'});
});
// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Users service running on port ${PORT}`);
});