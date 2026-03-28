const Database = require('better-sqlite3');

const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;


const db = new Database('totally_not_my_privateKeys.db');

//Create Table
db.exec(`
  CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`
)

// Insert Key
const insertKey = db.prepare('INSERT INTO keys(key, exp) VALUES (?, ?)');

async function storeKeyInDB(key, exp) {
  const pemKey = key.toPEM(true);
  insertKey.run(pemKey, exp);
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

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
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
  
  const keyList = [];

  ValidKeys.forEach(key => {
    keyList.push({
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n: jose.util.base64url.encode(jose.util.asBuffer(key.key).slice(0, 256)),
      e: jose.util.base64url.encode(jose.util.asBuffer(key.key).slice(256, 259))
    });
  });
  
  //const validKeys = [keyPair].filter(key => !key.expired);
  res.setHeader('Content-Type', 'application/json');
  res.json({ keys: keyList });
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    const expiredKey = db.prepare('SELECT * FROM keys WHERE exp < ?').get(Math.floor(Date.now() / 1000));
    if (!expiredKey) {
      return res.status(404).send('Expired Key Not Found');
    }
    //sign the expired token with the expired key
    //expiredToken = jwt.sign(jwt.decode(expiredToken), expiredKey.key, { algorithm: 'RS256' });
    return res.send(jwt.decode(expiredKey.key));
  }
  const validKey = db.prepare('SELECT * FROM keys WHERE exp > ?').get(Math.floor(Date.now() / 1000));
  if (!validKey) {
    return res.status(404).send('Valid Key Not Found');
  }
  //sign the token with the valid key
  //token = jwt.sign(jwt.decode(token), validKey.key, { algorithm: 'RS256' });
  res.send(jwt.decode(validKey.key));
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});

