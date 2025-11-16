/**
 * Circu.JS example: http file server
 * Before running this example, make sure to bundle tsrt.js into circu.js
 * run: `tsrt httpsrv.ts`
 */

import { FileResponse } from "./http";
import { createStaticFileServer } from "./static";
const { cwd } = import.meta.use('os');

const { createServer } = use('server');
const staticHandler = createStaticFileServer({
    root: cwd
});

createServer({
    port: 5666,
    address: '::',
    onRequest(req, res) {
        if (req.url.includes('..')) return res.send(403, 'Forbidden');
        if (!req.headers['host']) return res.send(400, 'Bad Request');
        if (req.url === '/') {
            req.url = '/index.html';
        }
        staticHandler(req, res);
    },
})