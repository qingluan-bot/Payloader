// Router dispatch 行为单测（同路径多 method 修复的直接覆盖）：
// ① 同路径 GET+PUT 双注册：两个 method 各自分发到各自 handler（修复前 PUT 一律 405）
// ② 未注册 method → 405 + Allow 聚合全部已注册方法
// ③ 组内无匹配 → dispatch 返回 false 交还调用方
import assert from 'node:assert/strict';
import test from 'node:test';
import { Router } from '../server/router.mjs';

const makeResponse = () => {
  const response = { statusCode: null, headers: null, body: '' };
  response.writeHead = (status, headers) => {
    response.statusCode = status;
    response.headers = headers;
  };
  response.end = chunk => {
    if (chunk) response.body = chunk;
  };
  return response;
};

test('同路径多 method：GET 与 PUT 各自分发，不再 405', async () => {
  const router = new Router();
  const hits = [];
  router.route(['GET'], '/api/admin/credentials', () => { hits.push('GET'); }, { group: 'admin' });
  router.route(['PUT'], '/api/admin/credentials', () => { hits.push('PUT'); }, { group: 'admin' });

  const putResponse = makeResponse();
  const putDispatched = await router.dispatch({ method: 'PUT' }, putResponse, new URL('http://x/api/admin/credentials'), 'admin', {});
  assert.equal(putDispatched, true);
  assert.deepEqual(hits, ['PUT']);
  assert.notEqual(putResponse.statusCode, 405);

  const getResponse = makeResponse();
  await router.dispatch({ method: 'GET' }, getResponse, new URL('http://x/api/admin/credentials'), 'admin', {});
  assert.deepEqual(hits, ['PUT', 'GET']);
});

test('未注册 method：405 且 Allow 头聚合全部已注册方法', async () => {
  const router = new Router();
  router.route(['GET'], '/thing', () => {}, { group: 'admin' });
  router.route(['PUT', 'POST'], '/thing', () => {}, { group: 'admin' });

  const response = makeResponse();
  const dispatched = await router.dispatch({ method: 'DELETE' }, response, new URL('http://x/thing'), 'admin', {});
  assert.equal(dispatched, true);
  assert.equal(response.statusCode, 405);
  // GET, POST, PUT 聚合排序（HEAD 不重复列出）
  assert.equal(response.headers.allow, 'GET, POST, PUT');
});

test('组内无匹配：dispatch 返回 false；其它组路由不参与', async () => {
  const router = new Router();
  router.route(['GET'], '/only-public', () => {}, { group: 'public' });

  const response = makeResponse();
  const dispatched = await router.dispatch({ method: 'GET' }, response, new URL('http://x/only-public'), 'admin', {});
  assert.equal(dispatched, false);
});

test('HEAD 推导自 GET；pattern 路由同路径 method 兼容同样生效', async () => {
  const router = new Router();
  const hits = [];
  router.route(['GET'], '/api/things/:id(\\d+)', () => { hits.push('GET'); }, { group: 'public' });
  router.route(['DELETE'], '/api/things/:id(\\d+)', () => { hits.push('DELETE'); }, { group: 'public' });

  const headResponse = makeResponse();
  await router.dispatch({ method: 'HEAD' }, headResponse, new URL('http://x/api/things/42'), 'public', {});
  assert.deepEqual(hits, ['GET']);

  const deleteResponse = makeResponse();
  await router.dispatch({ method: 'DELETE' }, deleteResponse, new URL('http://x/api/things/42'), 'public', {});
  assert.deepEqual(hits, ['GET', 'DELETE']);
  assert.notEqual(deleteResponse.statusCode, 405);
});
