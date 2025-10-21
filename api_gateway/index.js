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
        error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests - please try again later' }    }
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
    }, `Gateway: Request received for ${req.method} ${req.path}`);
    next();
});

const authenticateJWT = (req, res, next) => {
    if (req.path === '/v1/users/register' || req.path === '/v1/users/login' || req.path == '/v1/health') {
        logger.info({ requestId: req.requestId, path: req.path }, `Gateway: Skipping JWT for open endpoint ${req.method} ${req.path}`);
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn({ requestId: req.requestId, path: req.path }, `Gateway: Missing or invalid Authorization header for ${req.method} ${req.path}`); 
        return res.status(401).json({
            success: false,
            error: { code: 'UNAUTHORIZED', message: 'Authorization header missing or invalid for ' + req.method + ' ' + req.path }
        });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        logger.info({ requestId: req.requestId, userId: decoded.id, path: req.path }, `Gateway: JWT verified for ${req.method} ${req.path}, userId: ${decoded.id}`);
        next();
    } catch (err) {
        logger.error({ requestId: req.requestId, error: err.message, path: req.path }, `Gateway: Invalid token for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'INVALID_TOKEN', message: `Invalid or expired token for ${req.method} ${req.path}` }
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
        logger.info({ requestId: options.headers['X-Request-ID'], url }, `Gateway: Successful response from Users service for ${options.method || 'GET'} ${url}`);
        return response.data;
    } catch (error) {
        logger.error({ requestId: options.headers['X-Request-ID'], error: error.message, url }, `Gateway: Error response from Users service for ${options.method || 'GET'} ${url}`);
        throw error;
    }
}, circuitOptions);

const ordersCircuit = new CircuitBreaker(async (url, options = {}) => {
    try {
        const response = await axios({
            url, ...options,
            validateStatus: status => (status >= 200 && status < 300) || status === 404
        });
        logger.info({ requestId: options.headers['X-Request-ID'], url }, `Gateway: Successful response from Orders service for ${options.method || 'GET'} ${url}`);
        return response.data;
    } catch (error) {
        logger.error({ requestId: options.headers['X-Request-ID'], error: error.message, url }, `Gateway: Error response from Orders service for ${options.method || 'GET'} ${url}`);
        throw error;
    }
}, circuitOptions);

// Fallback functions
usersCircuit.fallback(() => ({
    success: false,
    error: { code: 'SERVICE_UNAVAILABLE', message: 'Users service temporarily unavailable - try again later' }
}));
ordersCircuit.fallback(() => ({
    success: false,
    error: { code: 'SERVICE_UNAVAILABLE', message: 'Orders service temporarily unavailable - try again later' }
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
app.get('/v1/users/:userId/details', authenticateJWT, async (req, res) => {
    const userId = req.params.userId;
    logger.info({ requestId: req.requestId, userId, path: req.path }, `Gateway: Fetching user details for ${req.method} ${req.path}`);
    if (req.user.id !== userId && req.user.role !== 'admin') {
        logger.warn({ requestId: req.requestId, userId: req.user.id, path: req.path }, `Gateway: Unauthorized user details access for ${req.method} ${req.path}`);
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: `Access denied for ${req.method} ${req.path}` }
        });
    }
    try {
        const userResponse = await axios.get(`${USERS_SERVICE_URL}/v1/users/${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });
        const ordersResponse = await axios.get(`${ORDERS_SERVICE_URL}/v1/orders?userId=${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });
        logger.info({ requestId: req.requestId, userId, path: req.path }, `Gateway: User and orders fetched successfully for ${req.method} ${req.path}`);
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
            error: error.message,
            path: req.path
        }, `Gateway: Error fetching user details for ${req.method} ${req.path}`);
        res.status(error.response?.status || 500).json({
            success: false,
            error: {
                code: error.response?.data?.error?.code || 'INTERNAL_ERROR',
                message: error.response?.data?.error?.message || `Internal server error for ${req.method} ${req.path}`
            }
        });
    }
});
app.use('/v1/users', createProxyMiddleware({
    target: USERS_SERVICE_URL,
    changeOrigin: true,
    on: {
        proxyReq: (proxyReq, req) => {
            proxyReq.setHeader('X-Request-ID', req.requestId);
            if (req.headers.authorization) {
                proxyReq.setHeader('Authorization', req.headers.authorization);
            }
            logger.info({
                requestId: req.requestId,
                target: USERS_SERVICE_URL,
                path: req.path
            }, `Gateway: Proxying to Users service for ${req.method} ${req.path}`);
        },
        proxyRes: (proxyRes, req) => {
            logger.info({
                requestId: req.requestId,
                statusCode: proxyRes.statusCode,
                path: req.path
            }, `Gateway: Response from Users service for ${req.method} ${req.path}`);
        }
    }
}));

app.use('/v1/orders', createProxyMiddleware({
    target: ORDERS_SERVICE_URL,
    changeOrigin: true,
    on: {
        proxyReq: (proxyReq, req) => {
            proxyReq.setHeader('X-Request-ID', req.requestId);
            if (req.headers.authorization) {
                proxyReq.setHeader('Authorization', req.headers.authorization);
            }
            logger.info({
                requestId: req.requestId,
                target: ORDERS_SERVICE_URL,
                path: req.path
            }, `Gateway: Proxying to Orders service for ${req.method} ${req.path}`);
        },
        proxyRes: (proxyRes, req) => {
            logger.info({
                requestId: req.requestId,
                statusCode: proxyRes.statusCode,
                path: req.path
            }, `Gateway: Response from Orders service for ${req.method} ${req.path}`);
        }
    }
}));

app.get('/v1/health', (req, res) => {
    logger.info({ requestId: req.requestId, path: req.path }, `Gateway: Health check performed for ${req.method} ${req.path}`);
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
    logger.info({ requestId: req.requestId, path: req.path }, `Gateway: Status check performed for ${req.method} ${req.path}`);
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