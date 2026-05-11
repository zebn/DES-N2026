const fs = require('fs');
const path = require('path');

// In Vercel, apiUrl is empty — services already include /api/ in their paths.
// The reverse proxy in vercel.json handles /api/* → backend.
// API_URL can override for other deployment targets.
const apiUrl = process.env.API_URL || '';

const content = `export const environment = {
  production: true,
  apiUrl: '${apiUrl}'
};
`;

const targetPath = path.join(__dirname, 'src', 'environments', 'environment.prod.ts');
fs.writeFileSync(targetPath, content);
console.log(`environment.prod.ts generated with apiUrl=${apiUrl}`);
