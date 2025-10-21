const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const pino = require('pino');
const { createProxyMiddleware } = require('http-proxy-middleware');
const CircuitBreaker = require('opossum');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';
const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'info' : 'debug' });
const USERS_SERVICE_URL = 'http://service_users:8002';
const ORDERS_SERVICE_URL = 'http://service_orders:8004';
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
    req.requestId = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.requestId);
    logger.info({
        requestId: req.requestId,
        method: req.method,
        url: req.url,
        path: req.path
    }, 'Gateway: Request received');
    next();
});

const authenticateJWT = (req, res, next) => {
    if (req.path === '/v1/users/register' || req.path === '/v1/users/login') {
        logger.info({ requestId: req.requestId, path: req.path }, 'Gateway: Skipping JWT for open endpoint');
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn({ requestId: req.requestId, path: req.path }, 'Gateway: Missing or invalid Authorization header');
        return res.status(401).json({
            success: false,
            error: { code: 'UNAUTHORIZED', message: 'Authorization header missing or invalid' }
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        logger.info({ requestId: req.requestId, userId: decoded.id, path: req.path }, 'Gateway: JWT verified');
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message, path: req.path }, 'Gateway: Invalid token');
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token' }
        });
    }
};

app.use(authenticateJWT);
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
            headers: {
                'Authorization': req.headers.authorization,
                'X-Request-ID': req.requestId
            },
            params: req.query
        });
        logger.info({ requestId: req.requestId }, 'Users list fetched');
        res.json(response.data); // Извлекаем данные из ответа
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error fetching users');
        res.status(error.response?.status || 500).json({
            success: false,
            error: {
                code: error.response?.data?.error?.code || 'INTERNAL_ERROR',
                message: error.response?.data?.error?.message || 'Internal server error'
            }
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


app.delete('/v1/orders/:orderId', authenticateJWT, async (req, res) => {
    try {
        const response = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders/${req.params.orderId}`, {
            method: 'DELETE',
            requestId: req.requestId,
            headers: { Authorization: req.headers.authorization }
        });
        if (!response.success) {
            logger.warn({ requestId: req.requestId, orderId: req.params.orderId }, 'Order deletion failed');
            return res.status(404).json(response);
        }
        logger.info({ requestId: req.requestId, orderId: req.params.orderId }, 'Order deleted');
        res.json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Error deleting order');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
        });
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
// Gateway Aggregation: Get user details with their orders
app.get('/v1/users/:userId/details', async (req, res) => {
    console.log("Reached /v1/users/:userId/details with userId:", req.params.userId, "and user:", req.user);
    const userId = req.params.userId;
    logger.info({ requestId: req.requestId, userId }, 'Gateway: Fetching user details');

    if (req.user.id !== userId && req.user.role !== 'admin') {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Gateway: Unauthorized user details access');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    try {
        const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });

        const ordersResponse = await axios.get(`${ORDERS_SERVICE_URL}/v1/orders?userId=${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });

        logger.info({ requestId: req.requestId, userId }, 'Gateway: User and orders fetched successfully');
        res.json({
            success: true,
            data: {
                user: userResponse.data.data,
                orders: ordersResponse.data.data.orders
            }
        });
    } catch (error) {
        logger.error({
            requestId: req.requestId,
            userId,
            error: error.message
        }, 'Gateway: Error fetching user details');
        res.status(error.response?.status || 500).json({
            success: false,
            error: {
                code: error.response?.data?.error?.code || 'INTERNAL_ERROR',
                message: error.response?.data?.error?.message || 'Internal server error'
            }
        });
    }
});
app.use('/v1/users', createProxyMiddleware({
    target: USERS_SERVICE_URL,
    changeOrigin: true,
    onProxyReq: (proxyReq, req) => {
        proxyReq.setHeader('X-Request-ID', req.requestId);
        if (req.headers.authorization) {
            proxyReq.setHeader('Authorization', req.headers.authorization);
        }
        logger.info({
            requestId: req.requestId,
            target: USERS_SERVICE_URL,
            path: req.path
        }, 'Gateway: Proxying to users service');
    },
    onProxyRes: (proxyRes, req) => {
        logger.info({
            requestId: req.requestId,
            statusCode: proxyRes.statusCode,
            path: req.path
        }, 'Gateway: Response from users service');
    }
}));

app.use('/v1/orders', createProxyMiddleware({
    target: ORDERS_SERVICE_URL,
    changeOrigin: true,
    onProxyReq: (proxyReq, req) => {
        proxyReq.setHeader('X-Request-ID', req.requestId);
        if (req.headers.authorization) {
            proxyReq.setHeader('Authorization', req.headers.authorization);
        }
        logger.info({
            requestId: req.requestId,
            target: ORDERS_SERVICE_URL,
            path: req.path
        }, 'Gateway: Proxying to orders service');
    },
    onProxyRes: (proxyRes, req) => {
        logger.info({
            requestId: req.requestId,
            statusCode: proxyRes.statusCode,
            path: req.path
        }, 'Gateway: Response from orders service');
    }
}));

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