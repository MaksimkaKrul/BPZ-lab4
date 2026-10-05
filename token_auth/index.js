const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUTH0_DOMAIN = 'maksim-im34-kpi-oauth2-lab2.eu.auth0.com'; 
const AUTH0_CLIENT_ID = 'egtDufBQZ6PTpmDh4u4m61ZFpUIJt6Mb'; 
const AUTH0_CLIENT_SECRET = 'yPCYAhgu2VpCOMcs7_MaLlBaWGkHK5xKzvQmDhOQSaMiLRmNLLnT63lxEqoVhzsp'; 

const SESSION_KEY = 'Authorization';
const JWT_SECRET = 'my_super_secret_key';

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
            sessionId = decoded.sessionId;
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

    if (req.session.username && req.session.auth0_refresh_token && req.session.expires_at) {
        const timeLeft = req.session.expires_at - Date.now();
        
        if (timeLeft < 300000) { 
            console.log(`[Auth0] Токен закінчується. Оновлюємо через Refresh Token...`);
            try {
                const refreshResponse = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
                    grant_type: 'refresh_token',
                    client_id: AUTH0_CLIENT_ID,
                    client_secret: AUTH0_CLIENT_SECRET,
                    refresh_token: req.session.auth0_refresh_token
                });
                
                req.session.auth0_access_token = refreshResponse.data.access_token;
                req.session.expires_at = Date.now() + (refreshResponse.data.expires_in * 1000);
                req.session.last_refresh = new Date().toLocaleTimeString(); 
                console.log("[Auth0] Токен успішно оновлено!");
            } catch (error) {
                console.error("[Auth0] Помилка оновлення", error.message);
            }
        }
    }

    onFinished(req, () => {
        sessions.set(req.sessionId, req.session);
    });

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({ 
            username: req.session.username,
            access_token: req.session.auth0_access_token,
            has_refresh_token: !!req.session.auth0_refresh_token,
            expires_at: req.session.expires_at,
            last_refresh: req.session.last_refresh || 'not checked'
        });
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'password',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            username: login,
            password: password,
            scope: 'openid profile email offline_access'
        });

        const auth0Data = response.data;
        req.session.username = login;
        req.session.auth0_access_token = auth0Data.access_token;
        req.session.auth0_refresh_token = auth0Data.refresh_token;
        req.session.expires_at = Date.now() + (auth0Data.expires_in * 1000); 
        req.session.last_refresh = 'not checked';

        const token = jwt.sign({ sessionId: req.sessionId }, JWT_SECRET);
        return res.json({ token: token });
    } catch (error) {
        res.status(401).send();
    }
});

app.post('/api/register', async (req, res) => {
    const { login, password } = req.body;
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
            client_id: AUTH0_CLIENT_ID,
            email: login,
            password: password,
            connection: 'Username-Password-Authentication'
        });
        res.json({ message: "Успішно зареєстровано!" });
    } catch (error) {
        res.status(400).json(error.response ? error.response.data : { message: "Помилка" });
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
});