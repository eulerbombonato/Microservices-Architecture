const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
app.use(express.json());

// Conectar ao MongoDB
mongoose.connect('mongodb://localhost:27017/seuBancoDeDados')
  .then(() => console.log('Conectado ao MongoDB'))
  .catch(err => console.error('Erro ao conectar ao MongoDB', err));

// Modelo do usuário
const userSchema = new mongoose.Schema({
  email: String,
  login: String,
  password: String
});

const User = mongoose.model('User', userSchema);

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - login
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: O e-mail do usuário.
 *         login:
 *           type: string
 *           description: O login do usuário.
 *         password:
 *           type: string
 *           description: A senha do usuário.
 *     Token:
 *       type: object
 *       properties:
 *         token:
 *           type: string
 *           description: O token JWT para autenticação.
 */

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Registra um novo usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: Usuário registrado com sucesso.
 *       500:
 *         description: Erro ao registrar usuário.
 */

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Realiza o login de um usuário.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               login:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login bem-sucedido com token retornado.
 *       401:
 *         description: Login ou senha inválidos.
 */

/**
 * @swagger
 * /users/{id}:
 *   put:
 *     summary: Atualiza informações do usuário.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID do usuário.
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               login:
 *                 type: string
 *     responses:
 *       200:
 *         description: Usuário atualizado.
 *       404:
 *         description: Usuário não encontrado.
 *       500:
 *         description: Erro ao atualizar o usuário.
 */

/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     summary: Exclui um usuário.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID do usuário.
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Usuário excluído com sucesso.
 *       404:
 *         description: Usuário não encontrado.
 *       500:
 *         description: Erro ao excluir o usuário.
 */

// Rota de registro
app.post('/register', async (req, res) => {
  const { email, login, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); // Hash a senha
  const user = new User({ email, login, password: hashedPassword });

  try {
    await user.save(); // Salva o usuário no banco de dados
    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
  } catch (err) {
    res.status(500).json({ message: 'Erro ao registrar usuário', error: err });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  const user = await User.findOne({ login });

  if (!user) {
    return res.status(401).json({ message: 'Login ou senha inválidos' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ message: 'Login ou senha inválidos' });
  }

  const token = jwt.sign({ id: user._id }, 'suaChaveSecreta', { expiresIn: '1h' });
  res.json({ token });
});

// Middleware de autenticação
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extrair o token do cabeçalho
  if (!token) {
    return res.sendStatus(403); // Acesso negado, token não encontrado
  }

  jwt.verify(token, 'suaChaveSecreta', (err, user) => {
    if (err) {
      return res.sendStatus(403); // Token inválido
    }
    req.user = user; // Adicionar informações do usuário à requisição
    next(); // Passar para o próximo middleware ou rota
  });
};

// Atualizar informações do usuário (PUT)
app.put('/users/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params; // Obter o ID do usuário da URL
  const { email, login } = req.body; // Obter os novos dados do corpo da requisição

  try {
    const updatedUser = await User.findByIdAndUpdate(id, { email, login }, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    res.json(updatedUser); // Retornar o usuário atualizado
  } catch (err) {
    res.status(500).json({ message: 'Erro ao atualizar o usuário', error: err });
  }
});

// Excluir usuário (DELETE)
app.delete('/users/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params; // Obter o ID do usuário da URL

  try {
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    res.json({ message: 'Usuário excluído com sucesso!' });
  } catch (err) {
    res.status(500).json({ message: 'Erro ao excluir o usuário', error: err });
  }
});

// Middleware para tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Algo deu errado!' });
});

// Swagger Documentation
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'API de Usuários',
      version: '1.0.0',
    },
  },
  apis: ['./app.js'], // O caminho dos arquivos onde as anotações Swagger estão
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs)); // Rota para acessar a documentação

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
