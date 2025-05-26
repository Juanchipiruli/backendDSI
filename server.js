const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('./data.json');
const middlewares = jsonServer.defaults();
const jwt = require('jsonwebtoken');

// Clave secreta para firmar los tokens JWT
const JWT_SECRET = 'clave_secreta_dsi_2025';
// Tiempo de expiración de tokens
const TOKEN_EXPIRATION = '24h'; // 24 horas
server.use(jsonServer.bodyParser);

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
  if (req.method === 'POST' && req.path === '/users') {
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

// Endpoint personalizado para login de usuario
server.post('/login', (req, res) => {
  const { legajo, password } = req.body;
  
  // Verificar que se proporcionaron legajo y password
  if (!legajo || !password) {
    return res.status(400).json({ 
      success: false,
      error: 'Se requieren legajo y password en el cuerpo de la solicitud' 
    });
  }
  
  // Obtener los datos de usuarios
  const db = router.db.getState();
  const usuarios = db.users || [];
  
  // Buscar el usuario con el legajo y password proporcionados
  const usuario = usuarios.find(u => u.legajo === legajo && u.password === password);
  
  if (usuario) {
    // Si se encuentra el usuario, generar token JWT
    const { password, ...usuarioInfo } = usuario;
    
    // Crear payload del token
    const payload = {
      legajo: usuario.legajo,
      nombre: usuario.nombre,
      role: 'user',
      isAdmin: false
    };
    
    // Generar token
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
    
    return res.status(200).json({ 
      success: true, 
      alumno: usuarioInfo,
      isAdmin: false,
      token: token
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
server.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  
  // Verificar que se proporcionaron username y password
  if (!username || !password) {
    return res.status(400).json({ 
      success: false,
      error: 'Se requieren username y password en el cuerpo de la solicitud' 
    });
  }
  
  // Obtener los datos de administradores
  const db = router.db.getState();
  const admins = db.admins || [];
  
  // Buscar el administrador con el username y password proporcionados
  const admin = admins.find(a => a.username === username && a.password === password);
  
  if (admin) {
    // Si se encuentra el administrador, generar token JWT
    const { password, ...adminInfo } = admin;
    
    // Crear payload del token
    const payload = {
      username: admin.username,
      nombre: admin.nombre,
      permisos: admin.permisos,
      role: 'admin',
      isAdmin: true
    };
    
    // Generar token
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRATION });
    
    return res.status(200).json({ 
      success: true, 
      usuario: adminInfo,
      isAdmin: true,
      token: token
    });
  } else {
    // Si no se encuentra el administrador, devolver un error
    return res.status(401).json({ 
      success: false, 
      error: 'Credenciales de administrador inválidas' 
    });
  }
});

// Middleware para verificar token JWT de usuario
const verificarToken = (req, res, next) => {
  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado. Se requiere un token de autenticación.'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // Verificar el token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Agregar la información del usuario al objeto de solicitud
    req.usuario = decoded;
    
    next(); // Continuar con la solicitud
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: 'Token inválido o expirado'
    });
  }
};

// Middleware para verificar si es administrador usando JWT
const verificarAdmin = (req, res, next) => {
  // Obtener el token del encabezado de autorización
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado. Se requiere un token de autenticación.'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    // Verificar el token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Verificar si el usuario es administrador
    if (!decoded.isAdmin || decoded.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Acceso denegado. Se requieren permisos de administrador.'
      });
    }
    
    // Agregar la información del administrador al objeto de solicitud
    req.admin = decoded;
    
    next(); // Continuar con la solicitud
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: 'Token inválido o expirado'
    });
  }
};

// Endpoint para obtener todos los usuarios (solo para administradores)
server.get('/admin/users/all', verificarAdmin, (req, res) => {
  try {
    // Obtener los datos de usuarios
    const db = router.db.getState();
    const usuarios = db.users || [];
    
    // Eliminar las contraseñas de los usuarios antes de enviarlos
    const usuariosSinPassword = usuarios.map(usuario => {
      const { password, ...usuarioInfo } = usuario;
      return usuarioInfo;
    });
    
    return res.status(200).json({
      success: true,
      usuarios: usuariosSinPassword
    });
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Endpoint para crear un nuevo usuario (solo para administradores)
server.post('/admin/users/add', verificarAdmin, (req, res) => {
  try {
    // Verificar que todos los campos requeridos estén presentes
    const requiredFields = ['legajo', 'password', 'nombre', 'dni', 'carrera', 'localidad'];
    const missingFields = requiredFields.filter(field => !req.body[field]);
    
    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Faltan campos requeridos',
        missingFields: missingFields
      });
    }
    
    // Obtener los datos actuales
    const db = router.db.getState();
    const usuarios = db.users || [];
    
    // Verificar si ya existe un usuario con el mismo legajo
    const usuarioExistente = usuarios.find(u => u.legajo === req.body.legajo);
    if (usuarioExistente) {
      return res.status(400).json({
        success: false,
        error: 'Ya existe un usuario con ese legajo'
      });
    }
    
    // Agregar el nuevo usuario
    const nuevoUsuario = req.body;
    usuarios.push(nuevoUsuario);
    
    // Guardar los cambios
    db.users = usuarios;
    router.db.setState(db);
    router.db.write();
    
    // Devolver respuesta exitosa (sin la contraseña)
    const { password, ...usuarioInfo } = nuevoUsuario;
    return res.status(201).json({
      success: true,
      usuario: usuarioInfo
    });
  } catch (error) {
    console.error('Error al crear usuario:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Endpoint para actualizar un usuario existente (solo para administradores)
server.put('/admin/users/update/:legajo', verificarAdmin, (req, res) => {
  try {
    const { legajo } = req.params;
    
    // Obtener los datos actuales
    const db = router.db.getState();
    const usuarios = db.users || [];
    
    // Buscar el índice del usuario a actualizar
    const usuarioIndex = usuarios.findIndex(u => u.legajo === legajo);
    
    if (usuarioIndex === -1) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado'
      });
    }
    
    // Actualizar los campos proporcionados
    const usuarioActualizado = {
      ...usuarios[usuarioIndex],
      ...req.body
    };
    
    // Mantener el legajo original
    usuarioActualizado.legajo = legajo;
    
    // Actualizar el usuario en el array
    usuarios[usuarioIndex] = usuarioActualizado;
    
    // Guardar los cambios
    db.users = usuarios;
    router.db.setState(db);
    router.db.write();
    
    // Devolver respuesta exitosa (sin la contraseña)
    const { password, ...usuarioInfo } = usuarioActualizado;
    return res.status(200).json({
      success: true,
      usuario: usuarioInfo
    });
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Endpoint para eliminar un usuario (solo para administradores)
server.delete('/admin/users/delete/:legajo', verificarAdmin, (req, res) => {
  try {
    const { legajo } = req.params;
    
    // Obtener los datos actuales
    const db = router.db.getState();
    const usuarios = db.users || [];
    
    // Buscar el índice del usuario a eliminar
    const usuarioIndex = usuarios.findIndex(u => u.legajo === legajo);
    
    if (usuarioIndex === -1) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado'
      });
    }
    
    // Eliminar el usuario del array
    usuarios.splice(usuarioIndex, 1);
    
    // Guardar los cambios
    db.users = usuarios;
    router.db.setState(db);
    router.db.write();
    
    return res.status(200).json({
      success: true,
      message: `Usuario con legajo ${legajo} eliminado correctamente`
    });
  } catch (error) {
    console.error('Error al eliminar usuario:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

// Endpoint para obtener información del perfil del usuario autenticado
server.get('/perfil', verificarToken, (req, res) => {
  try {
    // La información del usuario ya está disponible en req.usuario gracias al middleware verificarToken
    return res.status(200).json({
      success: true,
      usuario: req.usuario
    });
  } catch (error) {
    console.error('Error al obtener perfil:', error);
    return res.status(500).json({
      success: false,
      error: 'Error interno del servidor'
    });
  }
});

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
