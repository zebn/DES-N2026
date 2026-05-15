const fs = require('fs');
const path = require('path');

// API_URL should be API host/base only (without trailing slash and without /api).
// Service methods already append "/api/..." paths.
const rawApiUrl = process.env.API_URL || '';

function normalizeApiBase(value) {
  if (!value) return '';

  // Trim spaces and remove trailing slashes first.
  let normalized = value.trim().replace(/\/+$/, '');

  // If API_URL ends with /api, strip it to avoid /api/api in requests.
  normalized = normalized.replace(/\/api$/i, '');

  return normalized;
}

const apiUrl = normalizeApiBase(rawApiUrl);

const content = `export const environment = {
  production: true,
  apiUrl: '${apiUrl}'
};
`;

const targetPath = path.join(__dirname, 'src', 'environments', 'environment.prod.ts');
fs.writeFileSync(targetPath, content);
console.log(`environment.prod.ts generated with apiUrl=${apiUrl}`);
