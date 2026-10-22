import { apiBaseUrl } from './api-config';

describe('API endpoint configuration', () => {
  test.each([undefined, '', '   '])('defaults %p to the same-origin API', value => {
    expect(apiBaseUrl(value)).toBe('/api');
  });

  test.each([
    ['http://localhost:8000', 'http://localhost:8000/api'],
    ['https://vaptx.example/', 'https://vaptx.example/api'],
    [' https://vaptx.example/// ', 'https://vaptx.example/api'],
    ['/backend/', '/backend/api'],
  ])('normalizes %s', (value, expected) => {
    expect(apiBaseUrl(value)).toBe(expected);
  });
});
