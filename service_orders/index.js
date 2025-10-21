const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const EventEmitter = require('events');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const USERS_SERVICE_URL = process.env.USERS_SERVICE_URL || 'http://service_users:8002';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });
const eventEmitter = new EventEmitter();

// Middleware
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
    req.requestId = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    logger.info({ requestId: req.requestId, method: req.method, url: req.url }, `Orders: Request received for ${req.method} ${req.url}`);
    next();
});

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Orders: Missing or invalid Authorization header for ${req.method} ${req.path}`);
        return res.status(401).json({
            success: false,
            error: { code: 'UNAUTHORIZED', message: `Authorization header missing or invalid for ${req.method} ${req.path}` }
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        logger.info({ requestId: req.requestId, userId: decoded.id, path: req.path }, `Orders: JWT verified for ${req.method} ${req.path}, userId: ${decoded.id}`);
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message, path: req.path }, `Orders: Invalid token for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: `Invalid or expired token for ${req.method} ${req.path}` }
        });
    }
};

const orderSchema = Joi.object({
    userId: Joi.string().uuid().required(),
    description: Joi.string().min(1).required(),
    positions: Joi.array().items(
        Joi.object({
            product: Joi.string().min(1).required(),
            quantity: Joi.number().integer().min(1).required()
        })
    ).required(),
    total: Joi.number().min(0).required(),
    status: Joi.string().valid('created', 'in_progress', 'completed', 'cancelled').default('created')
});

let fakeOrdersDb = {};

app.post('/v1/orders', authenticateJWT, async (req, res) => {
    const { error, value } = orderSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Orders: Validation error for ${req.method} ${req.path}`);
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: `${error.details[0].message} for ${req.method} ${req.path}` }
        });
    }

    if (value.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Orders: Unauthorized order creation for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    try {
        const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${value.userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });
        if (!userResponse.data.success) {
            logger.warn({ requestId: req.requestId, userId: value.userId, path: req.path }, `Orders: User not found for ${req.method} ${req.path}`);
            return res.status(400).json({
                success: false,
                error: { code: 'USER_NOT_FOUND', message: `User does not exist for ${req.method} ${req.path}` }
            });
        }
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message, path: req.path }, `Orders: Error checking user existence for ${req.method} ${req.path}`);
        return res.status(400).json({
            success: false,
            error: { code: 'USER_NOT_FOUND', message: `User does not exist or service unavailable for ${req.method} ${req.path}` }
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
    logger.info({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order created successfully for ${req.method} ${req.path}, orderId: ${orderId}`);
    res.status(201).json({
        success: true,
        data: fakeOrdersDb[orderId]
    });
});

app.get('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `Order not found for ${req.method} ${req.path}` }
        });
    }

    if (order.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Orders: Unauthorized order access for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    logger.info({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order fetched successfully for ${req.method} ${req.path}, orderId: ${orderId}`);
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

    logger.info({ requestId: req.requestId, path: req.path }, `Orders: Orders list fetched successfully for ${req.method} ${req.path}, total: ${orders.length}`);
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

app.put('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `Order not found for ${req.method} ${req.path}` }
        });
    }

    if (order.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Orders: Unauthorized order update for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    const { error, value } = orderSchema.validate(req.body);
    if (error) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Orders: Validation error for ${req.method} ${req.path}`);
        return res.status(400).json({
            success: false,
            error: { code: 'VALIDATION_ERROR', message: `${error.details[0].message} for ${req.method} ${req.path}` }
        });
    }

    if (value.userId && value.userId !== order.userId) {
        try {
            const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${value.userId}`, {
                headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
            });
            if (!userResponse.data.success) {
                logger.warn({ requestId: req.requestId, userId: value.userId, path: req.path }, `Orders: User not found for ${req.method} ${req.path}`);
                return res.status(400).json({
                    success: false,
                    error: { code: 'USER_NOT_FOUND', message: `User does not exist for ${req.method} ${req.path}` }
                });
            }
        } catch (error) {
            logger.error({ requestId: req.requestId, error: error.message, path: req.path }, `Orders: Error checking user existence for ${req.method} ${req.path}`);
            return res.status(400).json({
                success: false,
                error: { code: 'USER_NOT_FOUND', message: `User does not exist or service unavailable for ${req.method} ${req.path}` }
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
    logger.info({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order updated successfully for ${req.method} ${req.path}, orderId: ${orderId}`);
    res.json({
        success: true,
        data: fakeOrdersDb[orderId]
    });
});

app.delete('/v1/orders/:orderId', authenticateJWT, (req, res) => {
    const orderId = req.params.orderId;
    const order = fakeOrdersDb[orderId];

    if (!order) {
        logger.warn({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order not found for ${req.method} ${req.path}`);
        return res.status(404).json({
            success: false,
            error: { code: 'NOT_FOUND', message: `Order not found for ${req.method} ${req.path}` }
        });
    }

    if (order.userId !== req.user.id && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Orders: Unauthorized order deletion for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }

    delete fakeOrdersDb[orderId];
    eventEmitter.emit('orderUpdated', { orderId, status: 'cancelled' });
    logger.info({ requestId: req.requestId, orderId, path: req.path }, `Orders: Order deleted successfully for ${req.method} ${req.path}, orderId: ${orderId}`);
    res.json({
        success: true,
        data: { message: 'Order deleted' }
    });
});

app.get('/v1/orders/health', (req, res) => {
    logger.info({ requestId: req.requestId, path: req.path }, `Orders: Health check performed for ${req.method} ${req.path}`);
    res.json({
        success: true,
        data: { status: 'OK', service: 'Orders Service', timestamp: new Date().toISOString() }
    });
});

app.get('/v1/orders/status', (req, res) => {
    logger.info({ requestId: req.requestId, path: req.path }, `Orders: Status check performed for ${req.method} ${req.path}`);
    res.json({ success: true, data: { status: 'Orders service is running' } });
});

eventEmitter.on('orderCreated', (event) => {
    logger.info({ event, path: 'event' }, `Orders: Order created event emitted: ${JSON.stringify(event)}`);
    console.log(`Publish to broker: orderCreated - ${JSON.stringify(event)}`);
});
eventEmitter.on('orderUpdated', (event) => {
    logger.info({ event, path: 'event' }, `Orders: Order updated event emitted: ${JSON.stringify(event)}`);
    console.log(`Publish to broker: orderUpdated - ${JSON.stringify(event)}`);
});

app.listen(PORT, () => {
    logger.info(`Orders service running on port ${PORT}`);
});