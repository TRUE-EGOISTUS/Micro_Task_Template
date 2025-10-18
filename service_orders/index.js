const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const EventEmitter = require('events');
const uuid = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:8002';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });
const eventEmitter = new EventEmitter(); // Для событий

// Middleware
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    req.requestId = req.headers['x-request-id'] || Date.now().toString();
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
        req.user = decoded;
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Invalid token');
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
        });
    }
};
const orderSchema = Joi.object({
    userId: Joi.string().uuid().required(), // UUID для userId
    description: Joi.string().min(1).required(),
    positions: Joi.array().items(
        Joi.object({
            product: Joi.string().min(1).required(),
            quantity: Joi.number().integer().min(1).required()
        })
    ).required(), // Состав заказа
    total: Joi.number().min(0).required(), // Итоговая сумма
    status: Joi.string().valid('created', 'in_progress', 'completed', 'cancelled').default('created')
});
// Имитация базы данных в памяти (LocalStorage)
let fakeOrdersDb = {};


// Routes

app.get('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId }, 'Order not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Order not found' }
        });
    }

    if (order.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order access');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    logger.info({ requestId: req.requestId, orderId }, 'Order fetched');
    res.json({
        success: true,
        data: order
    });
});

app.get('/v1/orders', authenticateJWT, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sort = req.query.sort || 'createdAt';
    const order = req.query.order || 'asc';

    let orders = Object.values(fakeOrdersDb);
    if (!req.user.roles.includes('admin')) {
        orders = orders.filter(o => o.userId === req.user.id);
    }

    orders.sort((a, b) => {
        const valA = a[sort] || '';
        const valB = b[sort] || '';
        return order === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    });

    const start = (page - 1) * limit;
    const paginatedOrders = orders.slice(start, start + limit);

    logger.info({ requestId: req.requestId }, 'Orders list fetched');
    res.json({
        success: true,
        data: {
            orders: paginatedOrders,
            page,
            limit,
            total: orders.length
        }
    });
});

app.post('/v1/orders', authenticateJWT, async (req, res) => {
    const { error, value } = orderSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId }, 'Validation error');
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
        });
    }

    if (value.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order creation');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    // Проверка существования пользователя
    try {
        const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${value.userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });
        if (!userResponse.data.success) {
            logger.warn({ requestId: req.requestId, userId: value.userId }, 'User not found');
            return res.status(400).json({
                success: false,
                error: { code: 'USER_NOT_FOUND', message: 'User does not exist' }
            });
        }
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error checking user existence');
        return res.status(400).json({
            success: false,
            error: { code: 'USER_NOT_FOUND', message: 'User does not exist or service unavailable' }
        });
    }

    const orderId = uuidv4();
    const now = new Date().toISOString();
    fakeOrdersDb[orderId] = {
        id: orderId,
        userId: value.userId,
        description: value.description,
        positions: value.positions,
        total: value.total,
        status: value.status,
        createdAt: now,
        updatedAt: now
    };

    eventEmitter.emit('orderCreated', { orderId, userId: value.userId });
    logger.info({ requestId: req.requestId, orderId }, 'Order created');
    res.status(201).json({
        success: true,
        data: fakeOrdersDb[orderId]
    });
});


app.put('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId }, 'Order not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Order not found' }
        });
    }

    if (order.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order update');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    const { error, value } = orderSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId }, 'Validation error');
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
        });
    }

    // Проверка существования пользователя (если userId меняется)
    if (value.userId && value.userId !== order.userId) {
        try {
            const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${value.userId}`, {
                headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
            });
            if (!userResponse.data.success) {
                logger.warn({ requestId: req.requestId, userId: value.userId }, 'User not found');
                return res.status(400).json({
                    success: false,
                    error: { code: 'USER_NOT_FOUND', message: 'User does not exist' }
                });
            }
        } catch (error) {
            logger.error({ requestId: req.requestId, error: error.message }, 'Error checking user existence');
            return res.status(400).json({
                success: false,
                error: { code: 'USER_NOT_FOUND', message: 'User does not exist or service unavailable' }
            });
        }
    }

    fakeOrdersDb[orderId] = {
        ...order,
        ...value,
        id: orderId,
        createdAt: order.createdAt,
        updatedAt: new Date().toISOString()
    };

    eventEmitter.emit('orderUpdated', { orderId, status: value.status });
    logger.info({ requestId: req.requestId, orderId }, 'Order updated');
    res.json({
        success: true,
        data: fakeOrdersDb[orderId]
    });
});

app.delete('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId }, 'Order not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Order not found' }
        });
    }

    if (order.userId !== req.user.id && req.user.role !== 'admin') {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order deletion');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    delete fakeOrdersDb[orderId];
    eventEmitter.emit('orderUpdated', { orderId, status: 'cancelled' });
    logger.info({ requestId: req.requestId, orderId }, 'Order deleted');
    res.json({
        success: true,
        data: { message: 'Order deleted' }
    });
});

app.get('/v1/orders/health', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Health check');
    res.json({
        success: true,
        data: { status: 'OK', service: 'Orders Service', timestamp: new Date().toISOString() }
    });
});

app.get('/v1/orders/status', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Status check');
    res.json({ success: true, data: { status: 'Orders service is running' } });
});

// Логирование событий (заготовка для брокера)
eventEmitter.on('orderCreated', (event) => {
    logger.info({ event }, 'Order created event');
    console.log(`Publish to broker: orderCreated - ${JSON.stringify(event)}`); // Заготовка
});
eventEmitter.on('orderUpdated', (event) => {
    logger.info({ event }, 'Order updated event');
    console.log(`Publish to broker: orderUpdated - ${JSON.stringify(event)}`); // Заготовка
});
// Start server
app.listen(PORT, () => {
   logger.info(`Orders service running on port ${PORT}`);
});