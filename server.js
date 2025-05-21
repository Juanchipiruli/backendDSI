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

// Middleware para validar los datos de alumnos en solicitudes POST
server.use((req, res, next) => {
  if (req.method === 'POST' && req.path === '/alumnos') {
    // Verificar que todos los campos requeridos estén presentes
    const requiredFields = ['legajo', 'password', 'nombre', 'dni', 'carrera', 'localidad'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({
        error: 'Faltan campos requeridos',
        missingFields: missingFields
      });
    }
    
    // Aquí puedes agregar más validaciones si es necesario
    // Por ejemplo, validar formato de DNI, longitud de legajo, etc.
    
    // Si todo está bien, continuar con la solicitud
    next();
  } else {
    // Para otras rutas o métodos, simplemente continuar
    next();
  }
});

// Endpoint personalizado para login
server.get('/login', (req, res) => {
  const { legajo, password } = req.query;
  
  // Verificar que se proporcionaron legajo y password
  if (!legajo || !password) {
    return res.status(400).json({ 
      error: 'Se requieren legajo y password como parámetros de consulta' 
    });
  }
  
  // Obtener los datos de usuarios
  const db = router.db.getState();
  const usuarios = db.users || []; // Cambiado de alumnos a users
  
  // Buscar el usuario con el legajo y password proporcionados
  const usuario = usuarios.find(u => u.legajo === legajo && u.password === password);
  
  if (usuario) {
    // Si se encuentra el usuario, devolver información básica (sin la contraseña)
    const { password, ...usuarioInfo } = usuario;
    return res.json({ 
      success: true, 
      alumno: usuarioInfo, // Mantener alumno para compatibilidad con tu frontend
      isAdmin: false
    });
  } else {
    // Si no se encuentra el usuario, devolver un error
    return res.status(401).json({ 
      success: false, 
      error: 'Credenciales inválidas' 
    });
  }
});

// Endpoint para login de administrador
server.get('/admin/login', (req, res) => {
  const { username, password } = req.query;
  
  // Verificar que se proporcionaron username y password
  if (!username || !password) {
    return res.status(400).json({ 
      error: 'Se requieren username y password como parámetros de consulta' 
    });
  }
  
  // Obtener los datos de administradores
  const db = router.db.getState();
  const admins = db.admins || [];
  
  // Buscar el administrador con el username y password proporcionados
  const admin = admins.find(a => a.username === username && a.password === password);
  
  if (admin) {
    // Si se encuentra el administrador, devolver información básica (sin la contraseña)
    const { password, ...adminInfo } = admin;
    return res.json({ 
      success: true, 
      usuario: adminInfo,
      isAdmin: true
    });
  } else {
    // Si no se encuentra el administrador, devolver un error
    return res.status(401).json({ 
      success: false, 
      error: 'Credenciales de administrador inválidas' 
    });
  }
});

// Middleware para verificar si es administrador
const verificarAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Admin ')) {
    return res.status(403).json({
      success: false,
      error: 'Acceso denegado. Se requieren permisos de administrador.'
    });
  }
  
  const adminData = authHeader.split(' ')[1];
  const [username, password] = Buffer.from(adminData, 'base64').toString().split(':');
  
  // Obtener los datos de administradores
  const db = router.db.getState();
  const admins = db.admins || [];
  
  // Verificar si existe un administrador con esas credenciales
  const esAdmin = admins.some(a => a.username === username && a.password === password);
  
  if (esAdmin) {
    next(); // Continuar con la solicitud
  } else {
    return res.status(403).json({
      success: false,
      error: 'Credenciales de administrador inválidas'
    });
  }
};

// Rutas protegidas que requieren autenticación de administrador
server.use('/admin/users', verificarAdmin);
server.use('/admin/config', verificarAdmin);

// Usar middlewares predeterminados (logger, static, cors y no-cache)
server.use(middlewares);

// Usar el enrutador
server.use(router);

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`JSON Server está corriendo en http://localhost:${PORT}`);
});