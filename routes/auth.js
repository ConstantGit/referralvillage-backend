const jwt = require('jsonwebtoken');

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const express = require('express');
const router = express.Router();

// Your authenticate middleware is fine as-is

// You'll need to add your actual routes here, for example:
// router.post('/login', async (req, res) => {
//   // login logic
// });

// router.post('/register', async (req, res) => {
//   // registration logic  
// });

module.exports = router;
