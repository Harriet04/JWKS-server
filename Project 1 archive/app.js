const express = require("express");
const fs = require("fs");
const jose = require("node-jose");
const router = express.Router(); 
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 8080;

app.use(express.json()); // Middleware to parse JSON bodies


let Token; // Global variable to store the generated token
let Key;
const kid = "my-key-id"; // Example Key ID, you can generate this dynamically
const expireTime = Math.floor(Date.now() / 1000) + 3600; // Token expires in 1 hour


const { generateKeyPairSync } = require('crypto');
const { stringify } = require("querystring");
const keystore = require("node-jose/lib/jwk/keystore");

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

console.log('Public Key:\n', publicKey);
console.log('Private Key:\n', privateKey);

const keyStore = jose.JWK.createKeyStore(); 
keyStore.generate("RSA", 2048, { alg: "RS256", use: "sig" }).then((result) => { 
    fs.writeFileSync( "Keys.json", JSON.stringify(keyStore.toJSON(true), null, " ") ); 
});

//save to localsto
fs.writeFileSync("publicKey.pem", publicKey);
fs.writeFileSync("privateKey.pem", privateKey);

// Load the keystore from the keys.json file
/*let keyStore;
try {
    const ks = fs.readFileSync("keys.json");
    keyStore = jose.JWK.asKeyStore(ks.toString());
} catch (error) {
    console.error("Error loading keys:", error);
    process.exit(1);
}
*/
router.get("/jwks", async (req, res) => { 
    const ks = fs.readFileSync("keys.json"); 
    const keyStore = await jose.JWK.asKeyStore(ks.toString());
    Key = keyStore.replace('{', '').replace('}', '').replace('"keys":', '').trim();
    console.log("in jwks get");console.log(Key);
    res.send(keyStore.toJSON()); 
}); 


router.get("/tokens", async (req, res) => { 
    const JWKeys = fs.readFileSync("keys.json"); 
    const keyStore = await jose.JWK.asKeyStore(JWKeys.toString()); 
    const [key] = keyStore.all({ use: "sig" }); 
    const opt = { compact: true, jwk: key, fields: { typ: "jwt" } }; 
    const kid = key.kid;
    const payload = JSON.stringify({ 
        exp: Math.floor((Date.now() + 3600000) / 1000), 
        iat: Math.floor(Date.now() / 1000), 
        sub: "test", 
    }); 
    const token = await jose.JWS.createSign(opt, key).update(payload).final(); 
console.log("in token get");console.log(token);
    //const token = jwt.sign({ sub: "test", exp: Math.floor((Date.now() + 3600000) / 1000) }, privateKey, { algorithm: "RS256", keyid: "my-key-id" });
    Token = token; // Store the generated token in the global variable
    console.log("Generated kid:", kid);
    console.log(Token);
    res.send({ token }); 
}); 

router.post("/auth", async (req, res) => 
    { let resourcePath = "token/jwks"; 
        let token = req.body; 
        let decodedToken = jwt.decode(token, { complete: true }); 
        let kid = decodedToken.headers.kid; 
        return new Promise(function (resolve, reject) { 
            var jwksPromise = config.request("GET", resourcePath); 
            jwksPromise .then(function (jwksResponse) { 
                const jwktopem = require("jwk-to-pem"); 
                const jwt = require("jsonwebtoken"); 
                const [firstKey] = jwksResponse.keys(kid); 
                const publicKey = jwktopem(firstKey); 
                try { const decoded = jwt.verify(token, publicKey); 
                    resolve(decoded); } catch (e) { reject(e); 

                    } 
                }) .catch(function (error) { reject(error); 

            }); 
        }); 
    }); 


// JWKS Endpoint
app.get("/.well-known/jwks.json", async (req, res) => {
    // Return only the public keys
    res.json(keyStore.toJSON());
});

app.use(router);

// Example protected endpoint (optional, for demonstration of verification logic)
app.get("/auth", async (req, res) => {
    //Token getting
    try{ const JWKeys = fs.readFileSync("keys.json"); 
        const keyStore = await jose.JWK.asKeyStore(JWKeys.toString()); 
        const [key] = keyStore.all({ use: "sig" }); 
        const opt = { compact: true, jwk: key, fields: { typ: "jwt" } }; 
        const kid = key.kid;
        const payload = JSON.stringify({ 
            exp: Math.floor((Date.now() + 3600000) / 1000), 
            iat: Math.floor(Date.now() / 1000), 
            sub: "test", 
        }); 
        const token = await jose.JWS.createSign(opt, key).update(payload).final(); 
        console.log("in token get");console.log(token);
        //const token = jwt.sign({ sub: "test", exp: Math.floor((Date.now() + 3600000) / 1000) }, privateKey, { algorithm: "RS256", keyid: "my-key-id" });
        Token = token; // Store the generated token in the global variable
        console.log("Generated kid:", kid);
        console.log(Token);
    }catch(error){
        console.error("Error generating token:", error);
        res.send("Internal Server Error for token generation");
    }

 
    try{  
    //res.send("This is a protected route. A client would verify a JWT against our JWKS endpoint.\n");
        console.log("Starting token verification...");
        
        const token = Token; // Use the generated token from the global variable
        if (!token) {
            return res.status(401).send("Missing token");
        }

         const result = await jose.JWS.createVerify(keyStore).verify(Token, {
            algorithms: ["RS256"]
        });
        console.log("Token verified successfully:", result);
        decodedToken = jwt.decode(Token, { complete: true });
        console.log("Decoded token:", decodedToken);
        //res.send("Token is valid. Decoded token: " + JSON.stringify(decodedToken));
    

        const keyData = { //store key data in object to push to keys array
        kid,
        publicKey,
        privateKey,
        expireTime
    };
    keyData.kid = result.key.kid;
    keyData.publicKey = decodedToken.signature; // Store the signature as the public key for demonstration
    keyData.privateKey = Token; // Store the signature as the private key for demonstration
    keyData.expireTime = decodedToken.payload.exp;
        res.json(keyData);
}
catch(error){
    console.error("Error verifying token:", error);
    res.send("Internal Server Error");
}
});

app.get("/", (req, res) => {
    res.send("Welcome to the JWKS server! Access the JWKS endpoint at /auth");
});

app.listen(PORT, () => {
    console.log(`JWKS server running on http://localhost:${PORT}`);
    console.log(`JWKS endpoint: http://localhost:${PORT}/.well-known/jwks.json`);
});



