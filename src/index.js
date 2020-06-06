const cookieParser = require("cookie-parser");
require("dotenv").config({ path: "variables.env" });
const jwt = require("jsonwebtoken");
const createServer = require("./createServer");
const db = require("./db");

const server = createServer();

// TODO Use express middleware to handle cookies (JWT)
server.express.use(cookieParser());
// TODO Use express middleware to populate current user
server.express.use((request, response, next) => {
  const { token } = request.cookies;
  if (token) {
    const { userId } = jwt.decode(token, process.env.APP_SECRET);
    request.userId = userId;
  }
  next();
});

server.express.use(async (request, response, next) => {
  if (!request.userId) return next();
  request.user = await db.query.user(
    { where: { id: request.userId } },
    `{id, email, name, permission}`
  );
  next();
});

server.start(
  {
    cors: {
      credentials: true,
      origin: process.env.FRONTEND_URL,
    },
  },
  (deets) => {
    console.log(`Server running on http://localhost:${deets.port}`);
  }
);
