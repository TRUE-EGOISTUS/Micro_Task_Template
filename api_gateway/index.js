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
        req.user = decoded; // decoded содержит id, roles (array)
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

// Circuit Breaker configuration
const circuitOptions = {
    timeout: 3000, // Timeout for requests (3 seconds)
    errorThresholdPercentage: 50, // Open circuit after 50% of requests fail
    resetTimeout: 3000, // Wait 3 seconds before trying to close the circuit
};

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
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });
        res.status(response.success ? 200 : response.error.status || 500).json(response);
    } catch (error) {
        logger.error({ requestId: req.requestId, error: error.message }, 'Gateway: Error fetching user');
        res.status(500).json({
            success: false,
            error: { code: 'INTERNAL_ERROR', message: 'Internal server error' }
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

// Gateway Aggregation: Get user details with their orders
app.get('/v1/users/:userId/details', authenticateJWT, async (req, res) => {
    const userId = req.params.userId;
    logger.info({ requestId: req.requestId, userId }, 'Gateway: Fetching user details');

    if (req.user.id !== userId && !req.user.roles.includes('admin')) {
        logger.warn({ requestId: req.requestId, userId: req.user.id }, 'Gateway: Unauthorized user details access');
        return res.status(403).json({
            success: false,
            error: { code: 'FORBIDDEN', message: 'Access denied' }
        });
    }

    try {
        // Запрос к users-сервису через circuit breaker
        const userResponse = await usersCircuit.fire(`${USERS_SERVICE_URL}/v1/users/${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });

        if (!userResponse.success) {
            logger.warn({ requestId: req.requestId, userId }, 'Gateway: User not found or service unavailable');
            return res.status(userResponse.error.status || 500).json(userResponse);
        }

        // Запрос к orders-сервису через circuit breaker
        const ordersResponse = await ordersCircuit.fire(`${ORDERS_SERVICE_URL}/v1/orders?userId=${userId}`, {
            headers: { 'X-Request-ID': req.requestId, Authorization: req.headers.authorization }
        });

        if (!ordersResponse.success) {
            logger.warn({ requestId: req.requestId, userId }, 'Gateway: Orders fetch failed');
            return res.status(ordersResponse.error.status || 500).json(ordersResponse);
        }

        logger.info({ requestId: req.requestId, userId }, 'Gateway: User and orders fetched successfully');
        res.json({
            success: true,
            data: {
                user: userResponse.data,
                orders: ordersResponse.data.orders
            }
        });
    } catch (error) {
        logger.error({
            requestId: req.requestId,
            userId,
            error: error.message
        }, 'Gateway: Error fetching user details');
        res.status(500).json({
            success: false,
            error: {
                code: 'INTERNAL_ERROR',
                message: 'Internal server error'
            }
        });
    }
});

// Health check endpoint
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