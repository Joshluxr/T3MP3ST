import { describe, expect, it } from 'vitest';
import { inspectCurlArgs } from '../server/curl-policy.js';

describe('hardened curl policy for /api/tools/execute', () => {
  it('binds curl to a single HTTP(S) URL operand', () => {
    expect(inspectCurlArgs(['https://approved.example/report', '-o', 'report.json'])).toEqual({
      target: 'https://approved.example/report',
    });
    expect(inspectCurlArgs(['-sS', '--output=result.json', 'https://approved.example/report'])).toEqual({
      target: 'https://approved.example/report',
    });
  });

  it.each([
    ['-L', 'https://example.com'],
    ['-sL', 'https://example.com'],
    ['--location', 'https://example.com'],
    ['--location-trusted', 'https://example.com'],
    ['-T', 'secrets.txt', 'https://example.com'],
    ['--upload-file=secrets.txt', 'https://example.com'],
    ['--data-binary', '@secrets.txt', 'https://example.com'],
    ['-d@secrets.txt', 'https://example.com'],
    ['-F', 'attachment=@secrets.txt', 'https://example.com'],
    ['-H', '@headers.txt', 'https://example.com'],
    ['--config', 'curl.conf', 'https://example.com'],
    ['--resolve', 'example.com:443:127.0.0.1', 'https://example.com'],
    ['--connect-to', 'example.com:443:other.example:443', 'https://example.com'],
    ['--proxy', 'http://proxy.example', 'https://example.com'],
    ['-xhttp://proxy.example', 'https://example.com'],
    ['--unix-socket', '/tmp/service.sock', 'http://localhost'],
  ])('fails closed for redirect/file/destination override: %j', (...args) => {
    expect(inspectCurlArgs(args as string[])).toHaveProperty('error');
  });

  it('rejects multiple, missing, and non-HTTP targets', () => {
    expect(inspectCurlArgs(['https://one.example', 'https://two.example'])).toHaveProperty('error');
    expect(inspectCurlArgs(['-sS'])).toHaveProperty('error');
    expect(inspectCurlArgs(['file:///etc/passwd'])).toHaveProperty('error');
    expect(inspectCurlArgs(['--unknown', 'value', 'https://example.com'])).toHaveProperty('error');
  });
});
