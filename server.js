const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('./data.json');
const middlewares = jsonServer.defaults();

// Configuración de CORS personalizada
server.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  
  // Manejar solicitudes preflight OPTIONS
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  
  next();
});

// Usar middlewares predeterminados (logger, static, cors y no-cache)
server.use(middlewares);

// Usar el enrutador
server.use(router);

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`JSON Server está corriendo en http://localhost:${PORT}`);
});