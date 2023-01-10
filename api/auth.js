const bodyParser = require('body-parser');
const config = require("../config");
const generator = require("../modules/generator.js");
const sanitize = require("../modules/sanitize");
const crypto = require('crypto');

module.exports.load = async function (app, db) {
  app.post('/api/auth/login', bodyParser.urlencoded({
    extended: true
  }), async (req, res) => {
    if (!req.body.name) {
      res.redirect("/login");
    }
    if (!req.body.pw) {
      res.redirect("/login");
    }
    const name = await sanitize.clean(req.body.name);
    const email = await sanitize.clean(req.body.email);
    const dbName = db.get(name, email);
    if (!dbName || dbName == null || dbName == "null") {
      res.redirect("/login?err=nf");
    } else {
      let saltHash = crypto.createHmac('sha256', dbName.salt);
      saltHash.update(req.body.pw);
      let pwHash = saltHash.digest('hex');
      if (pwHash == dbName.pw) {
        res.locals.name = name;
        req.session.loggedIn = true;
        req.session.name = res.locals.name;
        req.session.token = dbName.token;
        req.session.email = dbName.email;
        res.redirect('/dash');
      } else {
        res.redirect("/login?err=incorrect");
      }
    }
  });

  app.post("/api/auth/register", bodyParser.urlencoded({
    extended: true
  }), async (req, res) => {
    if (config.auth.require_register_key) {
      if (req.body.regKey != config.auth.register_key) {
        return res.redirect("/register");
      }
    }
    if (!req.body.name) {
      return res.redirect("/register?err=nf");
    }
    if (!req.body.pw) {
      return res.redirect("/register?err=nf");
    }
    if (!req.body.pw) {
      return res.redirect("/register?err=nf");
    }
    const name = await sanitize.clean(req.body.name);
    const email = await sanitize.clean(req.body.email);
    if(name == "") {
      return res.redirect("/register?err=nf");
    }
    if(email == "") {
      return res.redirect("/register?err=nf");
    }
    // Password hash
    const pwSalt = generator.gen(32)
    const saltHash = crypto.createHmac('sha256', pwSalt);
    saltHash.update(req.body.pw);
    const pwHash = saltHash.digest('hex');
    // Generate token
    const token = generator.gen(64);
    const checkName = db.get(name, email);
    if (!checkName) {
      db.set(name, {
        name: name,
        pw: pwHash,
        salt: pwSalt,
        token: token,
        email: email,
      });
      db.push("accountList", name);
      req.session.loggedIn = true;
      req.session.name = name;
      req.session.token = token;
      req.session.email = email;
      res.redirect("/dash");
    } else {
      res.status(401).redirect("/login?err=isUsed")
    }
  });
  app.post('/api/password', bodyParser.urlencoded({
    extended: true
  }), async (req, res) => {
    if (req.session.loggedIn) {
      if (!req.body.oldPw || !req.body.newPw) {
        res.redirect("/edit");
      }
      const name = await sanitize.clean(req.session.name);
      const email = await sanitize.clean(req.session.email);
      const dbName = db.get(name, email);
      const saltHash = crypto.createHmac('sha256', dbName.salt);
      saltHash.update(req.body.oldPw);
      const pwHash = saltHash.digest('hex');
      if (pwHash == dbName.pw) {
        const saltHash = crypto.createHmac('sha256', dbName.salt);
        saltHash.update(req.body.newPw);
        const pwHash = saltHash.digest('hex');
        const token = dbName.token;
        const pwSalt = dbName.salt;
        db.set(name, {
          name: name,
          pw: pwHash,
          salt: pwSalt,
          token: token,
          email: email,
        });
        delete req.session.loggedIn;
        res.redirect("/login");
      } else {
        res.redirect("/login");
      }
    }
  });
}