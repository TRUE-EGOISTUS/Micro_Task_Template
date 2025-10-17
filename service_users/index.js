const express = require('express');
const cors = require('cors');
const Joi = require('joi');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';

// Middleware
app.use(cors());
app.use(express.json());

// Имитация базы данных в памяти (LocalStorage)
let fakeUsersDb = {};
let currentId = 1;

const registerSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid('user', 'admin').default('user')
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

app.get('/users', (req, res) => {
    const users = Object.values(fakeUsersDb);
    res.json(users);
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

app.get('/users/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const user = fakeUsersDb[userId];

    if (!user) {
        return res.status(404).json({error: 'User not found'});
    }

    res.json(user);
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

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Users service running on port ${PORT}`);
});