"use strict";
var $node = require('rest-node');
var $J = $node.get().$J;
var AuthClient = (function () {
    function AuthClient(options, clientAppSettings) {
        this.options = options;
        this.clientAppSettings = clientAppSettings;
    }
    Object.defineProperty(AuthClient.prototype, "instance_url", {
        get: function () { return (this.options && this.options.instance_url ? this.options.instance_url : ''); },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(AuthClient.prototype, "redirect_uri", {
        get: function () { return (this.clientAppSettings && this.clientAppSettings.redirect_uri ? this.clientAppSettings.redirect_uri : null); },
        enumerable: true,
        configurable: true
    });
    AuthClient.prototype.getError = function (httpErr) {
        if (httpErr) {
            if (httpErr.responseJSON)
                return httpErr.responseJSON;
            else if (httpErr.responseText) {
                try {
                    return JSON.parse(httpErr.responseText);
                }
                catch (e) {
                    return httpErr.responseText;
                }
            }
            else
                return httpErr;
        }
        else
            return null;
    };
    AuthClient.getClientAppHeaderField = function () { return AuthClient.CLIENT_APP_HEADER_FLD; };
    Object.defineProperty(AuthClient.prototype, "connectOptions", {
        get: function () {
            var ret = {
                headers: {}
            };
            ret.headers[AuthClient.CLIENT_APP_HEADER_FLD] = JSON.stringify(this.clientAppSettings);
            if (this.options && typeof this.options.rejectUnauthorized)
                ret.rejectUnauthorized = this.options.rejectUnauthorized;
            return ret;
        },
        enumerable: true,
        configurable: true
    });
    // POST
    AuthClient.prototype.$P = function (path, data, done) {
        $J('POST', this.instance_url + path, data, done, this.connectOptions);
    };
    AuthClient.prototype.getConnectedApp = function (done) {
        var _this = this;
        this.$P("/services/authorize/get_connected_app", {}, function (err, connectedApp) {
            if (typeof done === 'function')
                done(_this.getError(err), connectedApp);
        });
    };
    AuthClient.prototype.userLogin = function (response_type, username, password, signUpUserForApp, done) {
        var _this = this;
        var params = {
            response_type: response_type,
            username: username,
            password: password,
            signUpUserForApp: signUpUserForApp
        };
        this.$P("/services/authorize/user_login", params, function (err, ret) {
            if (typeof done === 'function')
                done(_this.getError(err), ret);
        });
    };
    AuthClient.prototype.automationLogin = function (username, password, done) {
        var _this = this;
        var params = {
            username: username,
            password: password
        };
        this.$P("/services/authorize/automation_login", params, function (err, ret) {
            if (typeof done === 'function')
                done(_this.getError(err), ret);
        });
    };
    AuthClient.prototype.getAccessFromAuthCode = function (code, done) {
        var _this = this;
        var params = { code: code };
        this.$P("/services/authorize/get_access_from_auth_code", params, function (err, access) {
            if (typeof done === 'function')
                done(_this.getError(err), access);
        });
    };
    AuthClient.prototype.refreshToken = function (refresh_token, done) {
        var _this = this;
        var params = { refresh_token: refresh_token };
        this.$P("/services/authorize/refresh_token", params, function (err, access) {
            if (typeof done === 'function')
                done(_this.getError(err), access);
        });
    };
    AuthClient.prototype.SSPR = function (username, done) {
        var _this = this;
        var params = { username: username };
        this.$P("/services/authorize/sspr", params, function (err, data) {
            if (typeof done === 'function')
                done(_this.getError(err), data);
        });
    };
    AuthClient.prototype.resetPassword = function (pin, done) {
        var _this = this;
        var params = { pin: pin };
        this.$P("/services/authorize/reset_password", params, function (err, data) {
            if (typeof done === 'function')
                done(_this.getError(err));
        });
    };
    AuthClient.prototype.lookupUser = function (username, done) {
        var _this = this;
        var params = { username: username };
        this.$P("/services/authorize/lookup_user", params, function (err, data) {
            if (typeof done === 'function')
                done(_this.getError(err), data);
        });
    };
    AuthClient.prototype.signUpNewUser = function (accountOptions, done) {
        var _this = this;
        var params = accountOptions;
        this.$P("/services/authorize/sign_up_new_user", params, function (err, data) {
            if (typeof done === 'function')
                done(_this.getError(err), data);
        });
    };
    ;
    AuthClient.CLIENT_APP_HEADER_FLD = 'x-client-app';
    return AuthClient;
}());
exports.AuthClient = AuthClient;
var TokenVerifier = (function () {
    function TokenVerifier(options) {
        this.options = options;
    }
    TokenVerifier.prototype.getError = function (httpErr) {
        if (httpErr) {
            if (httpErr.responseJSON)
                return httpErr.responseJSON;
            else if (httpErr.responseText) {
                try {
                    return JSON.parse(httpErr.responseText);
                }
                catch (e) {
                    return httpErr.responseText;
                }
            }
            else
                return httpErr;
        }
        else
            return null;
    };
    Object.defineProperty(TokenVerifier.prototype, "instance_url", {
        get: function () { return (this.options && this.options.instance_url ? this.options.instance_url : ''); },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(TokenVerifier.prototype, "connectOptions", {
        get: function () {
            var ret = {
                headers: {}
            };
            if (this.options && typeof this.options.rejectUnauthorized)
                ret.rejectUnauthorized = this.options.rejectUnauthorized;
            return ret;
        },
        enumerable: true,
        configurable: true
    });
    // POST
    TokenVerifier.prototype.$P = function (path, data, done) {
        $J('POST', this.instance_url + path, data, done, this.connectOptions);
    };
    TokenVerifier.prototype.verifyAccessToken = function (accessToken, done) {
        var _this = this;
        var params = accessToken;
        this.$P("/services/token/verify", params, function (err, user) {
            if (typeof done === 'function')
                done(_this.getError(err), user);
        });
    };
    return TokenVerifier;
}());
