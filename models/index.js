var fs        = require("fs");
var path      = require("path");
var env       = process.env.NODE_ENV || "development";
var Sequelize = require('sequelize');
var secrets = require('../config/secrets')
var db        = {};

var sequelize = new Sequelize(secrets.db.name, secrets.db.username, secrets.db.password, {
  host: secrets.db.host,
  dialect: 'postgres',
  pool: {
    max: 5,
    min: 0,
    idle: 10000
  }
});

fs
  .readdirSync(__dirname)
  .filter(function(file) {
    return (file.indexOf(".") !== 0) && (file !== "index.js");
  })
  .forEach(function(file) {
    var model = sequelize.import(path.join(__dirname, file));
    db[model.name] = model;
  });

Object.keys(db).forEach(function(modelName) {
  if ("associate" in db[modelName]) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
