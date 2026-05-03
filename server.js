const Database = require('better-sqlite3');
const crypto = require('crypto');

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

app.use(express.json());

app.post('/auth', async (req, res) => {
  if (req.query.expired === 'true') {
    const expiredKey = db.prepare('SELECT * FROM keys WHERE exp < ?').get(Math.floor(Date.now() / 1000));
    if (!expiredKey) {
      return res.status(404).send('Expired Key Not Found');
    }
    const payload = {
      user: 'sampleUser',
      iat: Math.floor(Date.now() / 1000) - 30000,
      exp: Math.floor(Date.now() / 1000) - 3600
    };
    const signed = jwt.sign(payload, expiredKey.key, {
      algorithm: 'RS256',
      header: { typ: 'JWT', alg: 'RS256', kid: String(expiredKey.kid) }
    });
    return res.send(signed);
  }

  const validKey = db.prepare('SELECT * FROM keys WHERE exp > ?').get(Math.floor(Date.now() / 1000));
  if (!validKey) {
    return res.status(404).send('Valid Key Not Found');
  }
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const signed = jwt.sign(payload, validKey.key, {
    algorithm: 'RS256',
    header: { typ: 'JWT', alg: 'RS256', kid: String(validKey.kid) }
  });
  res.send(signed);
});

const db = new Database('totally_not_my_privateKeys.db');

//Create Key Table
db.exec(`
  CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`
);
//create user table
db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)`
);

//create auth_log table
db.exec(`
  CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
)`
);

// Insert Key
const insertKey = db.prepare('INSERT INTO keys(key, exp) VALUES (?, ?)');
// Insert User
const insertUser = db.prepare('INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)');
// Insert Auth Log
const insertAuthLog = db.prepare('INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)');


async function storeKeyInDB(key, exp) {
  const pemKey = (key.toPEM(true)).toString();
  insertKey.run(pemKey, exp);
}

async function storeUserInDB(username, password, email) {
  const password_hash = crypto.createHash('sha256').update(password).digest('hex'); 
    insertUser.run(username, password_hash, email);
}

async function storeAuthLog(requestIp, userId) {
  insertAuthLog.run(requestIp, userId);
}

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  storeKeyInDB(keyPair, payload.exp);
  const DBSign = db.prepare('SELECT * FROM keys WHERE key = ?').get(keyPair.toPEM(true));
  token = jwt.sign(payload, DBSign.key, options);
 
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };
  
  storeKeyInDB(expiredKeyPair, payload.exp);
  const DBSign = db.prepare('SELECT * FROM keys WHERE key = ?').get(expiredKeyPair.toPEM(true));
  expiredToken = jwt.sign(payload, DBSign.key, options);
  
}

app.post('/register', (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    return res.status(400).send('Username and email are required');
  }
  try {
    const password = crypto.randomUUID4();
    storeUserInDB(username, password, email);
    res.status(201).send('User registered successfully');
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).send('Username or email already exists');
    }
    res.status(500).send('Internal Server Error');
  }
});

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    if(req.method == 'GET'){
      return res.send("Method used = get");
    }
    return res.status(405).send('Method Not Allowed');

  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  const ValidKeys = db.prepare('SELECT * FROM keys WHERE exp > ?').all(Math.floor(Date.now() / 1000));
  
  
  //const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: ValidKeys.map(key => {
    const joseKey = jose.JWK.asKey(key.key, "pem");
    return joseKey.toJSON();
  })});
});


app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  
});

