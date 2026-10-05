const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH0_DOMAIN = 'maksim-im34-kpi-oauth2-lab2.eu.auth0.com'; 
const AUTH0_CLIENT_ID = 'egtDufBQZ6PTpmDh4u4m61ZFpUIJt6Mb'; 
const AUTH0_CLIENT_SECRET = 'yPCYAhgu2VpCOMcs7_MaLlBaWGkHK5xKzvQmDhOQSaMiLRmNLLnT63lxEqoVhzsp'; 
const REDIRECT_URI = 'http://localhost:3000';

const SESSION_KEY = 'Authorization';
const JWT_SECRET = 'my_super_secret_key';
const ENCRYPTION_KEY = '12345678901234567890123456789012';
const IV_LENGTH = 16;

function encryptPayload(text) {
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptPayload(text) {
    let textParts = text.split(':');
    let iv = Buffer.from(textParts.shift(), 'hex');
    let encryptedText = Buffer.from(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

class Session {
    #sessions = {}
    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
        } catch(e) { this.#sessions = {}; }
    }
    #storeSessions() { fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8'); }
    set(key, value) { this.#sessions[key] = value || {}; this.#storeSessions(); }
    get(key) { return this.#sessions[key]; }
    init(res) { const sessionId = uuid.v4(); this.set(sessionId); return sessionId; }
    destroy(req, res) { const sessionId = req.sessionId; delete this.#sessions[sessionId]; this.#storeSessions(); }
}

const sessions = new Session();

app.use(async (req, res, next) => {
    let currentSession = {};
    let token = req.get(SESSION_KEY);
    let sessionId;

    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            sessionId = decryptPayload(decoded.encryptedData); 
        } catch (err) {}
    }

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        sessions.set(req.sessionId, req.session);
    });

    next();
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname+'/index.html'));
});

app.get('/api/me', (req, res) => {
    if (req.session.username) {
        return res.json({ 
            username: req.session.username,
            access_token: req.session.auth0_access_token,
            id_token: req.session.auth0_id_token,
            expires_in: req.session.auth0_expires_in,
            token_type: req.session.auth0_token_type
        });
    }
    res.status(401).send();
});

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.get('/api/login', (req, res) => {
    const scope = encodeURIComponent('openid profile email');
    const auth0Url = `https://${AUTH0_DOMAIN}/authorize?client_id=${AUTH0_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${scope}`;
    res.redirect(auth0Url);
});

app.post('/api/callback', async (req, res) => {
    const { code } = req.body;
    try {
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('client_id', AUTH0_CLIENT_ID);
        params.append('client_secret', AUTH0_CLIENT_SECRET);
        params.append('code', code);
        params.append('redirect_uri', REDIRECT_URI);

        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const auth0Data = response.data;
        let username = 'Auth0 User';

        if (auth0Data.id_token) {
            const decodedIdToken = jwt.decode(auth0Data.id_token);
            if (decodedIdToken) {
                username = decodedIdToken.email || decodedIdToken.name || 'Auth0 User';
            }
        }

        req.session.username = username;
        req.session.auth0_access_token = auth0Data.access_token;
        req.session.auth0_id_token = auth0Data.id_token;
        req.session.auth0_expires_in = auth0Data.expires_in;
        req.session.auth0_token_type = auth0Data.token_type;

        const encryptedSession = encryptPayload(req.sessionId);
        const token = jwt.sign({ encryptedData: encryptedSession }, JWT_SECRET);
        
        return res.json({ token: token });
    } catch (error) {
        console.error(error.response ? error.response.data : error.message);
        res.status(401).send();
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});