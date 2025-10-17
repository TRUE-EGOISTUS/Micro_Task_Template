const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// Имитация базы данных в памяти (LocalStorage)
let fakeOrdersDb = {};
let currentId = 1;

// Routes
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

app.post('/orders', (req, res) => {
    const orderData = req.body;
    const orderId = currentId++;

    const newOrder = {
        id: orderId,
        ...orderData
    };

    fakeOrdersDb[orderId] = newOrder;
    res.status(201).json(newOrder);
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

// Start server
app.listen(PORT, () => {
    console.log(`Orders service running on port ${PORT}`);
});