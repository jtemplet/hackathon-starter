var _ = require('lodash');
var passport = require('passport');
var InstagramStrategy = require('passport-instagram').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GitHubStrategy = require('passport-github').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;
var OAuthStrategy = require('passport-oauth').OAuthStrategy; // Tumblr
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy; // Venmo, Foursquare
var models = require('../models');
var secrets = require('./secrets');

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    models.User.findById(id)
        .then(function(user) { done(null, user); })
        .catch(function(err) { done(err); });
});

// Sign in with Instagram.

passport.use(new InstagramStrategy(secrets.instagram,function(req, accessToken, refreshToken, profile, done) {
    if (req.user) {
        models.User.findOne({ where: {instagram: profile.id }}, function(err, existingUser) {
            if (existingUser) {
                req.flash('errors', { msg: 'There is already an Instagram account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                done(new Error('There is already an Instagram account that belongs to you.'));
            } else {
                models.User.findById(req.user.id, function(err, user) {
                    user.instagram = profile.id;
                    user.tokens.push({ kind: 'instagram', accessToken: accessToken });
                    user.profile.name = user.profile.name || profile.displayName;
                    user.profile.picture = user.profile.picture || profile._json.data.profile_picture;
                    user.profile.website = user.profile.website || profile._json.data.website;
                    models.User.update({
                            instagram: user.instagram,
                            tokens: user.tokens,
                            profile: user.profile
                        },
                        { where: { id: req.user.id} })
                        .then(function(u) {
                            req.flash('info', { msg: 'Instagram account has been linked.' });
                            done(null, u);
                        })
                        .catch(function(e) { done(e); });
                });
            }
        });
    } else {
        models.User.findOne({ where: { instagram: profile.id }}, function(err, existingUser) {
            if (existingUser) return done(null, existingUser);

            var user = { tokens: [], profile: {} };
            user.instagram = profile.id;
            user.tokens.push({ kind: 'instagram', accessToken: accessToken });
            user.profile.name = profile.displayName;
            // Similar to Twitter API, assigns a temporary e-mail address
            // to get on with the registration process. It can be changed later
            // to a valid e-mail address in Profile Management.
            user.email = profile.username + '@instagram.com';
            user.profile.website = profile._json.data.website;
            user.profile.picture = profile._json.data.profile_picture;
            models.User.create(user)
                .then(function(u) {
                    req.flash('info', { msg: 'Instagram account has been linked.' });
                    done(null, u);
                })
                .catch(function(e) { done(e); });
        });
    }
}));

// Sign in using Email and Password.

passport.use(new LocalStrategy({ usernameField: 'email' }, function(email, password, done) {
    models.User.findOne({ where: { email: email } })
        .then(function(user) {
            if (!user) return done(null, false, { message: 'Email ' + email + ' not found'});
            user.comparePassword(password, function(err, isMatch) {
                if (isMatch) {
                    return done(null, user);
                } else {
                    return done(null, false, { message: 'Invalid email or password.' });
                }
            });
        })
        .catch(function(err) {
            done(err);
        });

    // if (!user) return done(null, false, { message: 'Email ' + email + ' not found'});
    // user.comparePassword(password, function(err, isMatch) {
    //   if (isMatch) {
    //     return done(null, user);
    //   } else {
    //     return done(null, false, { message: 'Invalid email or password.' });
    //   }
    // });
}));

/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a <provider> id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */

// Sign in with Facebook.

passport.use(new FacebookStrategy(secrets.facebook, function(req, accessToken, refreshToken, profile, done) {
    if (req.user) {
        models.User.findOne({ where: { facebook: profile.id }})
            .then(function(existingUser) {
                if (existingUser) {
                    req.flash('errors', { msg: 'There is already a Facebook account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                    done(new Error('There is already a Facebook account that belongs to you'));
                } else {
                    models.User.findById(req.user.id)
                        .then(function(user) {
                            user.facebook = profile.id;
                            user.tokens.push({ kind: 'facebook', accessToken: accessToken });
                            user.profile.name = user.profile.name || profile.displayName;
                            user.profile.gender = user.profile.gender || profile._json.gender;
                            user.profile.picture = user.profile.picture || 'https://graph.facebook.com/' + profile.id + '/picture?type=large';

                            models.User.update({
                                    facebook: user.facebook,
                                    tokens: user.tokens,
                                    profile: user.profile
                                },
                                { where: { id: req.user.id} })
                                .then(function(u) {
                                    req.flash('info', { msg: 'Facebook account has been linked.' });
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        })
                        .catch(function(err) {
                            done(err);
                        });
                } // else
            });
    } else {
        models.User.findOne({ where: { facebook: profile.id }})
            .then(function(existingUser) {
                if (existingUser) return done(null, existingUser);
                models.User.findOne({ where: { email: profile._json.email }})
                    .then(function(existingEmailUser) {
                        if (existingEmailUser) {
                            req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings.' });
                            done(new Error('There is already an account using this email address'));
                        } else {
                            var user = { tokens: [], profile: {} };
                            user.email = profile._json.email;
                            user.facebook = profile.id;
                            user.tokens.push({ kind: 'facebook', accessToken: accessToken });
                            user.profile.name = profile.displayName;
                            user.profile.gender = profile._json.gender;
                            user.profile.picture = 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
                            user.profile.location = (profile._json.location) ? profile._json.location.name : '';
                            models.User.create(user)
                                .then(function(u) {
                                    req.flash('info', { msg: 'Facebook account has been linked.' });
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        } // else
                    })
                    .catch(function(err) {
                        done(err);
                    });
            })
            .catch(function(err) {
                done(err);
            });
    } // else
}));

// Sign in with GitHub.

passport.use(new GitHubStrategy(secrets.github, function(req, accessToken, refreshToken, profile, done) {
    if (req.user) {
        models.User.findOne({ where: { github: profile.id } })
            .then(function(existingUser) {
                if (existingUser) {
                    req.flash('errors', { msg: 'There is already a GitHub account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                    done(new Error('There is already a GitHub account that belongs to you.'));
                } else {
                    models.User.findById(req.user.id)
                        .then(function(user) {
                            user.github = profile.id;
                            user.tokens.push({ kind: 'github', accessToken: accessToken });
                            user.profile.name = user.profile.name || profile.displayName;
                            user.profile.picture = user.profile.picture || profile._json.avatar_url;
                            user.profile.location = user.profile.location || profile._json.location;
                            user.profile.website = user.profile.website || profile._json.blog;
                            models.User.update({
                                    github: user.github,
                                    tokens: user.tokens,
                                    profile: user.profile
                                },
                                { where: { id: req.user.id} })
                                .then(function(u) {
                                    req.flash('info', { msg: 'GitHub account has been linked.' });
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        });
                } // else
            }); // findOne()
    } else {
        models.User.findOne({ where: { github: '' + profile.id }})
            .then(function(existingUser) {
                if (existingUser) return done(null, existingUser);
                models.User.findOne({ where: { email: profile._json.email }})
                    .then(function(existingEmailUser) {
                        if (existingEmailUser) {
                            req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with GitHub manually from Account Settings.' });
                        } else {
                            var user = { tokens: [], profile: {} };
                            user.email = profile._json.email;
                            user.github = profile.id;
                            user.tokens.push({ kind: 'github', accessToken: accessToken });
                            user.profile.name = profile.displayName;
                            user.profile.picture = profile._json.avatar_url;
                            user.profile.location = profile._json.location;
                            user.profile.website = profile._json.blog;
                            models.User.create(user)
                                .then(function(u) {
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        } // else
                    }); // findOne()
            });  // findOne()
    } // else
}));

// Sign in with Twitter.

passport.use(new TwitterStrategy(secrets.twitter, function(req, accessToken, tokenSecret, profile, done) {
    if (req.user) {
        models.User.findOne({ where: { twitter: profile.id } })
            .then(function(existingUser) {
                if (existingUser) {
                    req.flash('errors', { msg: 'There is already a Twitter account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                    done(new Error('There is already a Twitter account that belongs to you.'));
                } else {
                    models.User.findById(req.user.id) //, function(err, user) {
                        .then(function(user) {
                            user.twitter = profile.id;
                            user.tokens.push({ kind: 'twitter', accessToken: accessToken, tokenSecret: tokenSecret });
                            user.profile.name = user.profile.name || profile.displayName;
                            user.profile.location = user.profile.location || profile._json.location;
                            user.profile.picture = user.profile.picture || profile._json.profile_image_url_https;
                            models.User.update({
                                twitter: user.twitter,
                                tokens: user.tokens,
                                profile: user.profile
                            }, { where: { id: req.user.id} })
                                .then(function(result) {
                                    req.flash('info', { msg: 'Twitter account has been linked.' });
                                    done(null, result);
                                })
                                .catch(function(err) {
                                    done(err);
                                }); // update
                        }); // findById
                } // else
            }); // findOne

    } else {
        models.User.findOne({ where: { twitter: profile.id }}) //, function(err, existingUser) {
            .then(function( existingUser) {
                if (existingUser) return done(null, existingUser);
                var user = { tokens: [], profile: {} };
                // Twitter will not provide an email address.  Period.
                // But a person’s twitter username is guaranteed to be unique
                // so we can "fake" a twitter email address as follows:
                user.email = profile.username + '@twitter.com';
                user.twitter = profile.id;
                user.tokens.push({ kind: 'twitter', accessToken: accessToken, tokenSecret: tokenSecret });
                user.profile.name = profile.displayName;
                user.profile.location = profile._json.location;
                user.profile.picture = profile._json.profile_image_url_https;
                models.User.create(user)
                    .then(function(u) {
                        req.flash('info', { msg: 'Twitter account has been linked.' });
                        done(null, u);
                    })
                    .catch(function(e) { done(e) });
            }); // findOne
    }
}));

// Sign in with Google.

passport.use(new GoogleStrategy(secrets.google, function(req, accessToken, refreshToken, profile, done) {
    if (req.user) {
        models.User.findOne({ where: { google: profile.id }})
            .then(function(existingUser) {
                if (existingUser) {
                    req.flash('errors', { msg: 'There is already a Google account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                    done(new Error('There is already a Google account that belongs to you.'));
                } else {
                    models.User.findById(req.user.id)
                        .then(function (user) {
                            user.google = profile.id;
                            user.tokens.push({ kind: 'google', accessToken: accessToken });
                            user.profile.name = user.profile.name || profile.displayName;
                            user.profile.gender = user.profile.gender || profile._json.gender;
                            user.profile.picture = user.profile.picture || profile._json.picture;
                            models.User.update({
                                google: user.google,
                                tokens: user.tokens,
                                profile: user.profile
                            }, { where: { id: req.user.id} })
                                .then(function(result) {
                                    req.flash('info', { msg: 'Google account has been linked.' });
                                    done(null, result);
                                })
                                .catch(function(err) {
                                    done(err);
                                }); // update
                        }) // findById
                        .catch(function(err) {
                            done(err);
                        });
                } // else
            });
    } else {
        models.User.findOne({ where: { google: profile.id }})
            .then(function(existingUser) {
                if (existingUser) return done(null, existingUser);
                models.User.findOne({ where: { email: profile._json.email }})
                    .then(function(existingEmailUser) {
                        if (existingEmailUser) {
                            req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Google manually from Account Settings.' });
                            done(new Error('There is already an account using this email address.'));
                        } else {
                            var user = { tokens: [], profile: {} };
                            user.email = profile._json.email;
                            user.google = profile.id;
                            user.tokens.push({ kind: 'google', accessToken: accessToken });
                            user.profile.name = profile.displayName;
                            user.profile.gender = profile._json.gender;
                            user.profile.picture = profile._json.picture;
                            models.User.create(user)
                                .then(function(u) {
                                    req.flash('info', { msg: 'Google account has been linked.' });
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        }
                    }); // findOne
            }); // findOne
    } // else
}));

// Sign in with LinkedIn.

passport.use(new LinkedInStrategy(secrets.linkedin, function(req, accessToken, refreshToken, profile, done) {
    if (req.user) {
        models.User.findOne({ where: { linkedin: profile.id } })
            .then(function(existingUser) {
                if (existingUser) {
                    req.flash('errors', { msg: 'There is already a LinkedIn account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
                    done(new Error('There is already a LinkedIn account that belongs to you.'));
                } else {
                    models.User.findById(req.user.id)
                        .then(function(user) {
                            user.linkedin = profile.id;
                            user.tokens.push({ kind: 'linkedin', accessToken: accessToken });
                            user.profile.name = user.profile.name || profile.displayName;
                            user.profile.location = user.profile.location || profile._json.location.name;
                            user.profile.picture = user.profile.picture || profile._json.pictureUrl;
                            user.profile.website = user.profile.website || profile._json.publicProfileUrl;
                            models.User.update({
                                linkedin: user.linkedin,
                                tokens: user.tokens,
                                profile: user.profile
                            }, { where: { id: req.user.id} })
                                .then(function(result) {
                                    req.flash('info', { msg: 'LinkedIn account has been linked.' });
                                    done(null, result);
                                })
                                .catch(function(err) {
                                    done(err);
                                }); // update
                        });  // findById()
                } // else
            }); // findOne()
    } else {
        models.User.findOne({ where: { linkedin: profile.id } } )
            .then(function(existingUser) {
                if (existingUser) return done(null, existingUser);
                models.User.findOne({ where: { email: profile._json.emailAddress } } )
                    .then(function(existingEmailUser) {
                        if (existingEmailUser) {
                            req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with LinkedIn manually from Account Settings.' });
                            done(new Error('There is already an account using this email address'));
                        } else {
                            var user = { tokens: [], profile: {} };
                            user.linkedin = profile.id;
                            user.tokens.push({ kind: 'linkedin', accessToken: accessToken });
                            user.email = profile._json.emailAddress;
                            user.profile.name = profile.displayName;
                            user.profile.location = profile._json.location.name;
                            user.profile.picture = profile._json.pictureUrl;
                            user.profile.website = profile._json.publicProfileUrl;
                            models.User.create(user)
                                .then(function(u) {
                                    req.flash('info', { msg: 'LinkedIn account has been linked.' });
                                    done(null, u);
                                })
                                .catch(function(e) { done(e); });
                        } // else
                    }); // findOne()
            }); // findOne()
    } // else
}));

// Tumblr API setup.

passport.use('tumblr', new OAuthStrategy({
        requestTokenURL: 'http://www.tumblr.com/oauth/request_token',
        accessTokenURL: 'http://www.tumblr.com/oauth/access_token',
        userAuthorizationURL: 'http://www.tumblr.com/oauth/authorize',
        consumerKey: secrets.tumblr.consumerKey,
        consumerSecret: secrets.tumblr.consumerSecret,
        callbackURL: secrets.tumblr.callbackURL,
        passReqToCallback: true
    },
    function(req, token, tokenSecret, profile, done) {
        models.User.findById(req.user.id)
            .then(function(user) {
                user.tokens.push({ kind: 'tumblr', accessToken: token, tokenSecret: tokenSecret });
                models.User.update({ tokens: user.tokens }, { where: { id: req.user.id} })
                    .then(function(result) {
                        req.flash('info', { msg: 'Tumblr account has been linked.' });
                        done(null, result);
                    })
                    .catch(function(err) {
                        done(err);
                    }); // update
            })
            .catch(function(err) {
                done(err);
            });
    }
));

// Foursquare API setup.

passport.use('foursquare', new OAuth2Strategy({
        authorizationURL: 'https://foursquare.com/oauth2/authorize',
        tokenURL: 'https://foursquare.com/oauth2/access_token',
        clientID: secrets.foursquare.clientId,
        clientSecret: secrets.foursquare.clientSecret,
        callbackURL: secrets.foursquare.redirectUrl,
        passReqToCallback: true
    },
    function(req, accessToken, refreshToken, profile, done) {
        models.User.findById(req.user.id)
            .then(function(user) {
                user.tokens.push({ kind: 'foursquare', accessToken: accessToken });
                models.User.update({ tokens: user.tokens }, { where: { id: req.user.id} })
                    .then(function(result) {
                        req.flash('info', { msg: 'Tumblr account has been linked.' });
                        done(null, result);
                    })
                    .catch(function(err) {
                        done(err);
                    }); // update
            }) // findById()
            .catch(function(err) {
                done(err);
            });
    }
));

// Venmo API setup.

passport.use('venmo', new OAuth2Strategy({
        authorizationURL: 'https://api.venmo.com/v1/oauth/authorize',
        tokenURL: 'https://api.venmo.com/v1/oauth/access_token',
        clientID: secrets.venmo.clientId,
        clientSecret: secrets.venmo.clientSecret,
        callbackURL: secrets.venmo.redirectUrl,
        passReqToCallback: true
    },
    function(req, accessToken, refreshToken, profile, done) {
        models.User.findById(req.user.id)
            .then(function(user) {
                user.tokens.push({ kind: 'venmo', accessToken: accessToken });
                models.User.update({ tokens: user.tokens }, { where: { id: req.user.id} })
                    .then(function(result) {
                        req.flash('info', { msg: 'Venmo account has been linked.' });
                        done(null, result);
                    })
                    .catch(function(err) {
                        done(err);
                    }); // update
            })
            .catch(function(err) {
                done(err);
            });
    }
));

// Login Required middleware.

exports.isAuthenticated = function(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
};

// Authorization Required middleware.

exports.isAuthorized = function(req, res, next) {
    var provider = req.path.split('/').slice(-1)[0];

    if (_.find(req.user.tokens, { kind: provider })) {
        next();
    } else {
        res.redirect('/auth/' + provider);
    }
};
