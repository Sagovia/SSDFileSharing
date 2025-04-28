const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const axios = require('axios');
const FormData = require('form-data');

const ITER = 100;

const jar = new CookieJar();
const client = wrapper(axios.create({
  baseURL: 'http://localhost:3000',
  jar,
  withCredentials: true,
}));

(async () => {
  // Get valid tokens
  const getRes = await client.get('/upload');
  const tokenMatch = getRes.data.match(/name="_csrf" value="([^"]+)"/);
  if (!tokenMatch) throw new Error("Couldn't find CSRF token in GET /upload");
  const token = tokenMatch[1];

  let blockedWithoutToken = 0;
  let allowedWithToken    = 0;

  // arrays to hold request lengths
  const noTokenTimes = [];
  const tokenTimes   = [];

  // No CSRF token
  await Promise.all(
    Array.from({ length: ITER }).map(async () => {
      const start = Date.now();
      try {
        const form = new FormData();
        form.append('file', Buffer.from('hello'), {
          filename: 'dummy.txt',
          contentType: 'text/plain'
        });

        const res = await client.post('/upload', form, {
          headers: form.getHeaders(),
          validateStatus: () => true
        });

        if (res.status === 403) blockedWithoutToken++;
      } catch (e) {
        console.error("no-token error (ignored):", e.message);
      } finally {
        noTokenTimes.push(Date.now() - start);
      }
    })
  );

  // With CSRF tokens
  await Promise.all(
    Array.from({ length: ITER }).map(async () => {
      const start = Date.now();
      try {
        const form = new FormData();
        form.append('_csrf', token);
        form.append('file', Buffer.from('hello'), {
          filename: 'dummy.txt',
          contentType: 'text/plain'
        });

        const res = await client.post('/upload', form, {
          headers: form.getHeaders(),
          validateStatus: () => true
        });

        if (res.status === 200) allowedWithToken++;
      } catch (e) {
        console.error("with-token error (ignored):", e.message);
      } finally {
        tokenTimes.push(Date.now() - start);
      }
    })
  );

  // Print out results, round to 1 decimal
  const avg = arr => arr.reduce((sum, t) => sum + t, 0) / arr.length;
  console.log(`No‐token blocked:   ${blockedWithoutToken}/${ITER} ` +
              `(${(blockedWithoutToken/ITER*100).toFixed(1)}%)` +
              ` — avg time ${(avg(noTokenTimes)).toFixed(1)} ms`);
  console.log(`With‐token allowed: ${allowedWithToken}/${ITER} ` +
              `(${(allowedWithToken/ITER*100).toFixed(1)}%)` +
              ` — avg time ${(avg(tokenTimes)).toFixed(1)} ms`);
})();

