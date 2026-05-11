const fs = require('fs');
const path = require('path');

// In Vercel, apiUrl should be empty — the reverse proxy in vercel.json
// handles /api/* → backend, so services use their own /api/ prefix directly.
// Strip trailing slash to prevent double-slash if API_URL is set externally.
const apiUrl = (process.env.API_URL || '').replace(/\/+$/, '');

const content = `export const environment = {
  production: true,
  apiUrl: '${apiUrl}'
};
`;

const targetPath = path.join(__dirname, 'src', 'environments', 'environment.prod.ts');
fs.writeFileSync(targetPath, content);
console.log(`environment.prod.ts generated with apiUrl=${apiUrl}`);
