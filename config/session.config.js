const MongoStore = require("connect-mongo");
const session = require("express-session");

module.exports = (app) => {
  app.set("trust proxy", 1);

  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: true,
      saveUninitilazed: false,
      cookie: {
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 60000,
      },
      store: MongoStore.create({
        mongoUrl:
          process.env.MONGODB_URI ||
          "mongodb://127.0.0.1:27017/lab-express-basic-auth",
      }),
    })
  );
};
