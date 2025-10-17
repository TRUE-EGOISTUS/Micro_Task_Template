const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const CircuitBreaker = require('opossum');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });
const limiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 минута
    max: 100, // Максимум 100 запросов
    message: {
        success: false,
        error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' }
    }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(limiter);

app.use((req, res, next) => {
    req.requestId = Date.now().toString();
    res.setHeader('X-Request-ID', req.requestId);
    logger.info({ requestId: req.requestId, method: req.method, url: req.url }, 'Request received');
    next();
});
// Service URLs
const USERS_SERVICE_URL = 'http://service_users:8000';
const ORDERS_SERVICE_URL = 'http://service_orders:8000';

const authenticateJWT = (req, res, next) => {
    if (req.path === '/v1/users/register' || req.path === '/v1/users/login') {
        return next(); // Пропускаем без токена
    }

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
// Circuit Breaker configuration
const circuitOptions = {
    timeout: 3000, // Timeout for requests (3 seconds)
    errorThresholdPercentage: 50, // Open circuit after 50% of requests fail
    resetTimeout: 3000, // Wait 30 seconds before trying to close the circuit
};

// Create circuit breakers for each service
const usersCircuit = new CircuitBreaker(async (url, options = {}) => {
    try {
        const response = await axios({
            url, ...options,
            validateStatus: status => (status >= 200 && status < 300) || status === 404
        });
        return response.data;
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return error.response.data;
        }
        throw error;
    }
}, circuitOptions);

const ordersCircuit = new CircuitBreaker(async (url, options = {}) => {
    try {
        const response = await axios({
            url, ...options,
            validateStatus: status => (status >= 200 && status < 300) || status === 404
        });
        return response.data;
    } catch (error) {
        if (error.response && error.response.status === 404) {
            return error.response.data;
        }
        throw error;
    }
}, circuitOptions);

// Fallback functions
usersCircuit.fallback(() => ({
    success: false,
    error: { code: 'SERVICE_UNAVAILABLE', message: 'Users service temporarily unavailable' }
}));
ordersCircuit.fallback(() => ({
    success: false,
    error: { code: 'SERVICE_UNAVAILABLE', message: 'Orders service temporarily unavailable' }
}));

// Routes with Circuit Breaker
app.get('/v1/users/:userId', authenticateJWT, async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/${req.params.userId}`, {
            requestId: req.requestId
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, userId: req.params.userId }, 'User not found');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, userId: req.params.userId }, 'User fetched');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error fetching user');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.post('/v1/users/register', async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/register`, {
            method: 'POST',
            data: req.body,
            requestId: req.requestId
        });
        logger.info({ requestId: req.requestId }, 'User registration forwarded');
        res.status(201).json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Registration error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.post('/v1/users/login', async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/login`, {
            method: 'POST',
            data: req.body,
            requestId: req.requestId
        });
        logger.info({ requestId: req.requestId }, 'User login forwarded');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Login error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.get('/v1/users', authenticateJWT, async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users`, {
            requestId: req.requestId
        });
        logger.info({ requestId: req.requestId }, 'Users list fetched');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error fetching users');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.delete('/v1/users/:userId', authenticateJWT, async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/${req.params.userId}`, {
            method: 'DELETE',
            requestId: req.requestId
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, userId: req.params.userId }, 'User deletion failed');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, userId: req.params.userId }, 'User deleted');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error deleting user');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});


app.put('/v1/users/:userId', authenticateJWT, async (req, res) => {
    try {
        const response = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/${req.params.userId}`, {
            method: 'PUT',
            data: req.body,
            requestId: req.requestId
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, userId: req.params.userId }, 'User update failed');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, userId: req.params.userId }, 'User updated');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error updating user');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});
app.get('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    try {
        const response = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}`, {
            requestId: req.requestId,
            headers: { Authorization: req.headers.authorization }
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, orderId: req.params.orderId }, 'Order not found');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, orderId: req.params.orderId }, 'Order fetched');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error fetching order');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.post('/v1/orders', authenticateJWT, async (req, res) => {
    try {
        const response = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders`, {
            method: 'POST',
            data: req.body,
            requestId: req.requestId,
            headers: { Authorization: req.headers.authorization }
        });
        logger.info({ requestId: req.requestId }, 'Order creation forwarded');
        res.status(201).json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Order creation error');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});
app.get('/v1/orders', authenticateJWT, async (req, res) => {
    try {
        const response = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders?page=${req.query.page || 1}&limit=${req.query.limit || 10}&sort=${req.query.sort || 'createdAt'}&order=${req.query.order || 'asc'}`, {
            requestId: req.requestId,
            headers: { Authorization: req.headers.authorization }
        });
        logger.info({ requestId: req.requestId }, 'Orders list fetched');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error fetching orders');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.delete('/orders/:orderId', async (req, res) => {
    try {
        const result = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/orders/${req.params.orderId}`, {
            method: 'DELETE'
        });
        res.json(result);
    } catch (error) {
        res.status(500).json({error: 'Internal server error'});
    }
});

app.put('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    try {
        const response = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}`, {
            method: 'PUT',
            data: req.body,
            requestId: req.requestId,
            headers: { Authorization: req.headers.authorization }
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, orderId: req.params.orderId }, 'Order update failed');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, orderId: req.params.orderId }, 'Order updated');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error updating order');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
    }
});

app.get('/orders/status', async (req, res) => {
    try {
        const status = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/orders/status`);
        res.json(status);
    } catch (error) {
        res.status(500).json({error: 'Internal server error'});
    }
});

app.get('/orders/health', async (req, res) => {
    try {
        const health = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/orders/health`);
        res.json(health);
    } catch (error) {
        res.status(500).json({error: 'Internal server error'});
    }
});

// Gateway Aggregation: Get user details with their orders
app.get('/users/:userId/details', async (req, res) => {
    try {
        const userId = req.params.userId;

        // Get user details
        const userPromise = usersCircuit.fire(`${USERS_SERVICE_URL}/users/${userId}`);

        // Get user's orders (assuming orders have a userId field)
        const ordersPromise = ordersCircuit.fire(`${ORDERS_SERVICE_URL}/orders`)
            .then(orders => orders.filter(order => order.userId == userId));

        // Wait for both requests to complete
        const [user, userOrders] = await Promise.all([userPromise, ordersPromise]);

        // If user not found, return 404
        if (user.error === 'User not found') {
            return res.status(404).json(user);
        }

        // Return aggregated response
        res.json({
            user,
            orders: userOrders
        });
    } catch (error) {
        res.status(500).json({error: 'Internal server error'});
    }
});

// Health check endpoint that shows circuit breaker status
app.get('/v1/health', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Health check');
    res.json({
        success: true,
        data: {
            status: 'API Gateway is running',
            circuits: {
                users: { status: usersCircuit.status, stats: usersCircuit.stats },
                orders: { status: ordersCircuit.status, stats: ordersCircuit.stats }
            }
        }
    });
});

app.get('/v1/status', (req, res) => {
    logger.info({ requestId: req.requestId }, 'Status check');
    res.json({ success: true, data: { status: 'API Gateway is running' } });
});

// Start server
app.listen(PORT, () => {
    logger.info(`API Gateway running on port ${PORT}`);
    usersCircuit.on('open', () => logger.info('Users circuit breaker opened'));
    usersCircuit.on('close', () => logger.info('Users circuit breaker closed'));
    usersCircuit.on('halfOpen', () => logger.info('Users circuit breaker half-open'));
    ordersCircuit.on('open', () => logger.info('Orders circuit breaker opened'));
    ordersCircuit.on('close', () => logger.info('Orders circuit breaker closed'));
    ordersCircuit.on('halfOpen', () => logger.info('Orders circuit breaker half-open'));
});