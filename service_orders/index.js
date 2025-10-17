const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const EventEmitter = require('events');

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
    userId: Joi.number().integer().required(),
    description: Joi.string().min(1).required(),
    status: Joi.string().valid('created', 'in_progress', 'completed', 'cancelled').default('created')
});
// Имитация базы данных в памяти (LocalStorage)
let fakeOrdersDb = {};
let currentId = 1;

// Routes

app.get('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const order = fakeOrdersDb[orderId];

    if (!order) {
        return res.status(404).json({error: 'Order not found'});
    }

    res.json(order);
});

app.get('/orders', (req, res) => {
    let orders = Object.values(fakeOrdersDb);

    // Добавляем фильтрацию по userId если передан параметр
    if (req.query.userId) {
        const userId = parseInt(req.query.userId);
        orders = orders.filter(order => order.userId === userId);
    }

    res.json(orders);
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

app.put('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);
    const orderData = req.body;

    if (!fakeOrdersDb[orderId]) {
        return res.status(404).json({error: 'Order not found'});
    }

    fakeOrdersDb[orderId] = {
        id: orderId,
        ...orderData
    };

    res.json(fakeOrdersDb[orderId]);
});

app.delete('/orders/:orderId', (req, res) => {
    const orderId = parseInt(req.params.orderId);

    if (!fakeOrdersDb[orderId]) {
        return res.status(404).json({error: 'Order not found'});
    }

    const deletedOrder = fakeOrdersDb[orderId];
    delete fakeOrdersDb[orderId];

    res.json({message: 'Order deleted', deletedOrder});
});

app.get('/orders/status', (req, res) => {
    res.json({status: 'Orders service is running'});
});

app.get('/orders/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'Orders Service',
        timestamp: new Date().toISOString()
    });
});
// Start server
app.listen(PORT, () => {
    console.log(`Orders service running on port ${PORT}`);
});