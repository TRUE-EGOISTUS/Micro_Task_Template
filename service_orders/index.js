const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const EventEmitter = require('events');
const uuid = require('uuid');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
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
let currentId = 1;

// Routes

app.get('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId }, 'Order not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Order not found' }
        });
    }

    if (order.userId !== req.user.id && req.user.role !== 'admin') {
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
    if (req.user.role !== 'admin') {
        orders = orders.filter(o => o.userId === req.user.id);
    }

    // Сортировка
    orders.sort((a, b) => {
        if (order === 'asc') {
            return a[sort] > b[sort] ? 1 : -1;
        } else {
            return a[sort] < b[sort] ? 1 : -1;
        }
    });

    // Пагинация
    const start = (page - 1) * limit;
    const paginatedOrders = orders.slice(start, start + limit);

    logger.info({ requestId: req.requestId, userId: req.user.id }, 'Orders list fetched');
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
    try {
        const { error, value } = orderSchema.validate(req.body);
        if (error) {
            logger.warn({ requestId: req.requestId, error: error.details }, 'Validation failed');
            return res.status(400).json({
                success: false,
                error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
            });
        }

        if (value.userId !== req.user.id) {
            logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order creation');
            return res.status(403).json({
                success: false,
                error: { code: 'FORBIDDEN', message: 'Can only create orders for yourself' }
            });
        }

        const orderId = currentId++;
        const newOrder = {
            id: orderId,
            userId: value.userId,
            description: value.description,
            status: value.status,
            createdAt: new Date().toISOString()
        };

        fakeOrdersDb[orderId] = newOrder;
        eventEmitter.emit('orderCreated', { orderId, userId: value.userId, description: value.description });
        logger.info({ requestId: req.requestId, orderId }, 'Order created');
        res.status(201).json({
            success: true,
            data: newOrder
        });
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message }, 'Order creation error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Server error' }
        });
    }
});

app.put('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId }, 'Order not found');
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: 'Order not found' }
        });
    }

    if (order.userId !== req.user.id && req.user.role !== 'admin') {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Unauthorized order update');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    const { error, value } = orderSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId, error: error.details }, 'Validation failed');
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: error.details[0].message }
        });
    }

    fakeOrdersDb[orderId] = {
        ...order,
        ...value,
        id: orderId,
        createdAt: order.createdAt
    };

    eventEmitter.emit('orderUpdated', { orderId, status: value.status });
    logger.info({ requestId: req.requestId, orderId }, 'Order updated');
    res.json({
        success: true,
        data: fakeOrdersDb[orderId]
    });
});

app.delete('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = parseInt(req.params.orderId);
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
});
eventEmitter.on('orderUpdated', (event) => {
    logger.info({ event }, 'Order updated event');
});
// Start server
app.listen(PORT, () => {
   logger.info(`Orders service running on port ${PORT}`);
});