var bcrypt = require('bcrypt-nodejs');
var crypto = require('crypto');

module.exports = function(sequelize, DataTypes) {
  var User = sequelize.define('User', {
    username: { type: DataTypes.STRING, unique: true },
    email: { type: DataTypes.STRING, unique: true },
    password: DataTypes.STRING,
    facebook: DataTypes.STRING,
    google: DataTypes.STRING,
    github: DataTypes.STRING,
    instagram: DataTypes.STRING,  
    twitter: DataTypes.STRING,
    tokens: DataTypes.ARRAY(DataTypes.JSON),
    profile: { type: DataTypes.JSON, defaultValue: { name: '', gender: '', location: '', website: '', picture: ''} },
    resetPasswordToken: DataTypes.STRING,
    resetPasswordExpires: DataTypes.DATE
  }, {
    classMethods: {
      associate: function(models) {}
    },
    instanceMethods: {
      comparePassword: function(candidatePassword, cb) {
        console.log('candidatePassword = ' + candidatePassword + ' => ' + this.password)
        bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
          if (err) { return cb(err); }
          cb(null, isMatch);
        });
      },
      gravatar: function(size) {
        if (!size) { size = 200; }

        if (!this.email) {
          return 'https://gravatar.com/avatar/?s=' + size + '&d=retro';
        }

        var md5 = crypto.createHash('md5').update(this.email).digest('hex');
        return 'https://gravatar.com/avatar/' + md5 + '?s=' + size + '&d=retro';
      }
    },
    hooks: {
      beforeCreate: function (user, options, cb) {
        bcrypt.genSalt(5, function(err, salt) {
          if (err) { return cb(err); }
          bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) { return cb(err); }
            user.password = hash;
            cb(null, user);
          });
        });
      }
    } // hooks
  })
  return User;
};


// var userSchema = new mongoose.Schema({
//   email: { type: String, unique: true, lowercase: true },
//   password: String,
//
//   facebook: String,
//   twitter: String,
//   google: String,
//   github: String,
//   instagram: String,
//   linkedin: String,
//   tokens: Array,
//
//   profile: {
//     name: { type: String, default: '' },
//     gender: { type: String, default: '' },
//     location: { type: String, default: '' },
//     website: { type: String, default: '' },
//     picture: { type: String, default: '' }
//   },
//
//   resetPasswordToken: String,
//   resetPasswordExpires: Date
// });
//
