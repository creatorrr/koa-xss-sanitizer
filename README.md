# Koa XSS Sanitizer

> Based on [express-xss-sanitizer](https://www.npmjs.com/package/express-xss-sanitizer)
Koa middleware which sanitizes user input data (in req.body, req.query, req.headers and req.params) to prevent Cross Site Scripting (XSS) attack.

## Installation
```bash
$ npm install koa-xss-sanitizer
```
## Usage
Add as a piece of express middleware, before defining your routes.
```
const Koa = require('koa');
const bodyParser = require('koa-bodyparser');
const { xss } = require('koa-xss-sanitizer');

const app = new Koa();

app.use(bodyParser());
app.use(xss());
```
You can add options to specify allowed keys to be skipped at sanitization
```
const options = {
   allowedKeys: ['name']
}

app.use(xss(options));
```
You can add options to specify allowed tags to sanitize it and remove other tags
```
const options = {
   allowedTags: ['h1']
}

app.use(xss(options));
```
You also can sanitize your data (object, array, string,etc) on the fly.
```
const { sanitize } = require(koa-xss-sanitizer');

// ...
      data = sanitize(data)
// or
      data = sanitize(data, {allowedKeys: ['name']})
// ...
```
## Tests
To run the test suite, first install the dependencies, then run `npm test`:
```bash
$ npm install
$ npm test
```
