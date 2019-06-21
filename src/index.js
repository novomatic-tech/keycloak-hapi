const KeycloakConfig = require('keycloak-connect/middleware/auth-utils/config');
const GrantManager = require('keycloak-connect/middleware/auth-utils/grant-manager');
const Token = require('keycloak-connect/middleware/auth-utils/token');
const Grant = require('keycloak-connect/middleware/auth-utils/grant');
const UUID = require('keycloak-connect/uuid');
const Boom = require('boom');
const _ = require('lodash');
const pkg = require('../package.json');
const crypto = require('crypto');
const urljoin = require('url-join');

const getProtocol = (request) => request.headers['x-forwarded-proto'] || request.server.info.protocol;
const getHost = (request) => request.headers['x-forwarded-host'] || request.info.host;

const throwError = (message) => {
    throw new Error(message)
};

const tokenRules = {
    exists: (token) => token || throwError('Invalid token (missing)'),
    notExpired: (token) => (token.content.exp || token.content.expiration) * 1000 > Date.now() || throwError('Invalid token (expired)'),
    signed: (token) => token.signed || throwError('Invalid token (not signed)'),
    validAction: (token, action) => token.content.action === action || throwError('Invalid token (wrong action)'),
    validResource: (token, resource) => token.content.resource === resource || throwError('Invalid token (wrong resource)'),
    validSignature: async (token, grantManager) => {
        const verify = crypto.createVerify('RSA-SHA256');
        if (grantManager.publicKey) {
            verify.update(token.signed);
            if (!verify.verify(grantManager.publicKey, token.signature, 'base64')) {
                throwError('Invalid token (signature)')
            }
        } else {
            const key = await grantManager.rotation.getJWK(token.header.kid);
            verify.update(token.signed);
            if (!verify.verify(key, token.signature)) {
                throwError('Invalid token (signature)')
            }
        }
    }
};

class ActionTokenVerifier {

    constructor(grantManager) {
        this.grantManager = grantManager;
    }

    async verify(token, {action, resource}) {
        tokenRules.exists(token);
        tokenRules.notExpired(token);
        tokenRules.signed(token);
        tokenRules.validAction(token, action);
        tokenRules.validResource(token, resource);
        await tokenRules.validSignature(token, this.grantManager);
        return token;
    }

}

class SessionGrantStore {
    constructor(options = null) {
        this.options = Object.assign({
            key: 'kc_auth_grant'
        }, options);
        this.name = 'session';
    }

    canRetrieveGrantFrom(request) {
        return !!this.getGrant(request);
    }

    getGrant(request) {
        return request.yar.get(this.options.key);
    }

    saveGrant(request, grant) {
        request.yar.set(this.options.key, grant);
    }

    clearGrant(request) {
        request.yar.reset();
    }
}

class BearerGrantStore {

    constructor() {
        this.name = 'bearer';
    }

    canRetrieveGrantFrom(request) {
        const header = request.headers.authorization;
        if (!header) {
            return false;
        }
        return header.indexOf('bearer ') === 0 || header.indexOf('Bearer ') === 0;
    }

    getGrant(request) {
        if (!this.canRetrieveGrantFrom(request)) {
            return null;
        }
        const accessToken = request.headers.authorization.substring('bearer '.length);
        return {
            access_token: accessToken
        };
    }
}

class NoGrantStore {

    canRetrieveGrantFrom() {
        return true;
    }

    getGrant() {
        return null;
    }
}

class DelegatingGrantStore {
    constructor(innerGrantStore, serializer) {
        this.innerGrantStore = innerGrantStore;
        this.serializer = serializer;
    }

    canRetrieveGrantFrom(request) {
        return this.innerGrantStore.canRetrieveGrantFrom(request);
    }

    getGrant(request) {
        const grant = this.innerGrantStore.getGrant(request);
        return grant ? this.serializer.deserialize(grant) : null;
    }

    saveGrant(request, grant) {
        if (!this.innerGrantStore.saveGrant) {
            return;
        }
        const grantData = this.serializer.serialize(grant);
        this.innerGrantStore.saveGrant(request, grantData);

    }

    clearGrant(request) {
        if (this.innerGrantStore.clearGrant) {
            this.innerGrantStore.clearGrant(request);
        }
    }
}

class GrantSerializer {

    constructor(clientId) {
        this.clientId = clientId;
    }

    serialize(grant) {
        if (!grant) {
            return null;
        }
        return {
            access_token: grant.access_token ? grant.access_token.token : undefined,
            refresh_token: grant.refresh_token ? grant.refresh_token.token : undefined,
            id_token: grant.id_token ? grant.id_token.token : undefined,
            expires_in: grant.expires_in,
            token_type: grant.token_type
        };
    }

    deserialize(grantData) {
        if (!grantData) {
            return null;
        }
        return new Grant({
            access_token: (grantData.access_token ? new Token(grantData.access_token, this.clientId) : undefined),
            refresh_token: (grantData.refresh_token ? new Token(grantData.refresh_token, this.clientId) : undefined),
            id_token: (grantData.id_token ? new Token(grantData.id_token, this.clientId) : undefined),
            expires_in: grantData.expires_in,
            token_type: grantData.token_type,
            __raw: grantData
        });
    }
}

const createPrincipalResource = (principal) => {
    if (!principal) {
        return principal;
    }
    const {name, scope, accessToken, idToken} = principal;
    const formattedPrincipal = {
        name,
        scope,
        accessToken: {
            value: accessToken.token,
            content: accessToken.content
        }
    };
    if (idToken) {
        formattedPrincipal.idToken = {
            value: idToken.token,
            content: idToken.content
        };
    }
    return formattedPrincipal;
};

const defaultPrincipalConversion = (principal) => principal;
const defaultShouldRedirectUnauthenticated = (config) => (request) => {
    return !(config.bearerOnly || request.auth.mode !== 'required' || request.raw.req.url.startsWith('/api/') || request.headers['x-requested-with'] === 'XMLHttpRequest');
};

const hapi17ReplyStrategy = (reply) => {
    return {
        authenticated: (options) => reply.authenticated(options),
        representation: (obj) => obj
    };
};

const hapi16ReplyStrategy = (reply) => {
    return {
        authenticated: (options) => reply.continue(options),
        representation: (obj) => reply(obj)
    };
};

class KeycloakAdapter {

    constructor(server, config) {
        this.server = server;
        this.config = Object.assign({
            loginUrl: '/sso/login',
            logoutUrl: '/sso/logout',
            principalUrl: '/api/principal',
            corsOrigin: ['*'],
            principalConversion: defaultPrincipalConversion,
            principalNameAttribute: 'name',
            shouldRedirectUnauthenticated: defaultShouldRedirectUnauthenticated(config)
        }, config);
        if (!this.config.secret) {
            this.config.secret = this.config.clientSecret;
        }
        this.keycloakConfig = new KeycloakConfig(this.config);
        this.grantManager = new GrantManager(this.keycloakConfig);
        this.actionTokenVerifier = new ActionTokenVerifier(this.grantManager);
        this.grantSerializer = new GrantSerializer(this.config.clientId);
        this.grantStores = this.createGrantStores(this.config.bearerOnly);
        this.replyStrategy = server.version < '17'
            ? hapi16ReplyStrategy
            : hapi17ReplyStrategy;
    }

    createGrantStores(bearerOnly) {
        const stores = [];
        stores.push(new BearerGrantStore());
        if (!bearerOnly) {
            stores.push(new SessionGrantStore());
        }
        stores.push(new NoGrantStore());
        return stores;
    }

    obtainGrantFromCode(code, redirectUri, sessionId, sessionHost) {
        const req = {
            session: {auth_redirect_uri: redirectUri}
        };
        return this.grantManager.obtainFromCode(req, code, sessionId, sessionHost);
    }

    getLoginUrl(redirectUrl, stateUuid = null) {
        return this.keycloakConfig.realmUrl +
            '/protocol/openid-connect/auth' +
            '?client_id=' + encodeURIComponent(this.keycloakConfig.clientId) +
            '&state=' + encodeURIComponent(stateUuid || UUID()) +
            '&redirect_uri=' + encodeURIComponent(redirectUrl) +
            '&scope=openid' +
            '&response_type=code';
    }

    getLogoutUrl({redirectUrl, idTokenHint}) {
        return urljoin(
            this.keycloakConfig.realmUrl,
            '/protocol/openid-connect/logout',
            redirectUrl ? '?redirect_uri=' + encodeURIComponent(redirectUrl) : '',
            idTokenHint ? '?id_token_hint=' + encodeURIComponent(idTokenHint) : '');
    }

    getChangePasswordUrl() {
        return urljoin(this.keycloakConfig.realmUrl, '/account/password',
            `?referrer=${encodeURIComponent(this.keycloakConfig.clientId)}`);
    }

    getAccountUrl() {
        return urljoin(this.keycloakConfig.realmUrl, '/account',
            `?referrer=${encodeURIComponent(this.keycloakConfig.clientId)}`);
    }

    getBaseUrl(request) {
        const base = this.config.baseUrl || urljoin(`${getProtocol(request)}://${getHost(request)}`, this.config.basePath || '');
        return urljoin(base, this.server.realm.modifiers.route.prefix || '');
    }

    getLoginRedirectUrl(request) {
        return urljoin(this.getBaseUrl(request), this.config.loginUrl, '?auth_callback=1');
    }

    getAssignedRoles(accessToken) {
        const appRoles = _.get(accessToken, `content.resource_access['${this.keycloakConfig.clientId}'].roles`, []);
        const realmRoles = _.get(accessToken, 'content.realm_access.roles', []);
        return _.union(appRoles, realmRoles);
    }

    getGrantStoreFor(request) {
        const grantStore = _.find(this.grantStores, store => store.canRetrieveGrantFrom(request));
        return new DelegatingGrantStore(grantStore, this.grantSerializer);
    }

    getGrantStoreByName(name) {
        const grantStore = _.find(this.grantStores, store => store.name === name);
        return new DelegatingGrantStore(grantStore, this.grantSerializer);
    }

    async authenticate(request, reply) {
        const log = this.server.log.bind(this.server);
        const grantStore = this.getGrantStoreFor(request);
        const existingGrant = grantStore.getGrant(request);
        if (!existingGrant) {
            log(['debug', 'keycloak'], 'No authorization grant received.');
            return null;
        }
        try {
            let grant = existingGrant;
            if (this.grantManager.isGrantRefreshable(grant)) {
                grant = await this.grantManager.ensureFreshness(grant);
                if (grant !== existingGrant) {
                    log(['debug', 'keycloak'], `Access token has been refreshed: ${grant}`);
                    grant = await this.grantManager.validateGrant(grant);
                    grantStore.saveGrant(request, grant);
                }
            } else {
                grant = await this.grantManager.validateGrant(grant);
            }
            return this.getPrincipal(grant);
        } catch (err) {
            log(['warn', 'keycloak'], `Authorization has failed - Received grant is invalid: ${err}.`);
            grantStore.clearGrant(request);
            return null;
        }
    };

    answer(reply) {
        return this.replyStrategy(reply);
    }

    getAuthScheme() {
        const keycloak = this;
        return (server, options) => {
            return {
                authenticate: async (request, reply) => {
                    const credentials = await keycloak.authenticate(request, reply);
                    server.log(['debug', 'keycloak'], `Authentication request. URL: ${request.raw.req.url}, user: ${credentials ? credentials.name : '[Anonymous]'}`);
                    if (credentials) {
                        return keycloak.answer(reply).authenticated({credentials});
                    } else {
                        if (keycloak.config.shouldRedirectUnauthenticated(request)) {
                            const loginUrl = keycloak.getLoginUrl(keycloak.getLoginRedirectUrl(request));
                            server.log(['debug', 'keycloak'], `User is not authenticated - redirecting to ${loginUrl}`);
                            return reply.response().takeover().redirect(loginUrl);
                        } else {
                            return keycloak.answer(reply).representation(Boom.unauthorized('The resource owner is not authenticated.', 'bearer', {realm: keycloak.config.realm}));
                        }
                    }
                }
            };
        };
    }

    getPrincipal(grant) {
        return {
            name: this.getPrincipalName(grant),
            scope: this.getAssignedRoles(grant.access_token),
            idToken: grant.id_token,
            accessToken: grant.access_token
        };
    }

    getPrincipalName(grant) {
        const principalNameAttribute = this.config.principalNameAttribute;
        let principalName;
        if (grant.id_token && grant.id_token.content[principalNameAttribute]) {
            principalName = grant.id_token.content[principalNameAttribute];
        } else if (grant.access_token.content[principalNameAttribute]) {
            principalName = grant.access_token.content[principalNameAttribute];
        } else {
            this.server.log(['warn', 'keycloak'], `Neither ID token nor access token contains '${principalNameAttribute}' attribute. Using 'sub' instead.`);
            principalName = grant.access_token.content.sub;
        }
        return principalName;
    }

    register() {
        this.server.auth.scheme('keycloak', this.getAuthScheme.bind(this)());
        if (!this.config.bearerOnly) {
            registerLoginRoute(this);
            registerLogoutRoute(this);
            registerBackChannelLogoutRoute(this);
        }
        if (this.config.principalUrl) {
            registerPrincipalRoute(this);
        }
    }
}

const registerPrincipalRoute = (keycloak) => {
    keycloak.server.route({
        path: keycloak.config.principalUrl,
        method: 'GET',
        handler: (request, reply) => {         // eslint-disable-line
            let principal = createPrincipalResource(request.auth.credentials);
            if (principal && !keycloak.config.bearerOnly) {
                principal = Object.assign({}, principal, {
                    accountUrl: keycloak.getAccountUrl(),
                    changePasswordUrl: keycloak.getChangePasswordUrl(),
                    logoutUrl: urljoin(keycloak.getBaseUrl(request), keycloak.config.logoutUrl),
                    loginUrl: urljoin(keycloak.getBaseUrl(request), keycloak.config.loginUrl)
                });
            }
            if (keycloak.config.principalConversion) {
                principal = keycloak.config.principalConversion(principal);
            }
            return keycloak.answer(reply).representation(principal || Boom.unauthorized('The user is not authenticated'));
        }
    });
};

const registerLoginRoute = (keycloak) => {
    const log = keycloak.server.log.bind(keycloak.server);
    keycloak.server.route({
        path: keycloak.config.loginUrl,
        method: 'GET',
        handler: async (request, reply) => {
            const grantStore = keycloak.getGrantStoreByName('session');
            if (grantStore.canRetrieveGrantFrom(request)) {
                return reply.redirect(keycloak.getBaseUrl(request));
            }
            const redirectUrl = keycloak.getLoginRedirectUrl(request);
            if (!request.query.auth_callback) {
                const loginUrl = keycloak.getLoginUrl(redirectUrl);
                log(['debug', 'keycloak'], `User is not authenticated - redirecting to ${loginUrl}`);
                return reply.redirect(loginUrl);
            } else {
                log(['debug', 'keycloak'], `Processing Keycloak callback after redirection to ${request.raw.req.url}`);
                if (request.query.error) {
                    const errorMessage = `Unable to authenticate - ${request.query.error}. ${request.query.error_description || ''}`;
                    log(['error', 'keycloak'], errorMessage);
                    return keycloak.answer(reply).representation(Boom.forbidden(errorMessage));
                }
                try {
                    log(['debug', 'keycloak'], `Processing authorization code`);
                    const grant = await keycloak.obtainGrantFromCode(request.query.code, redirectUrl, request.yar.id, keycloak.getBaseUrl(request));
                    grantStore.saveGrant(request, grant);
                    log(['debug', 'keycloak'], `Access token has been successfully obtained from the authorization code:\n${grant}`);
                    return reply.redirect(keycloak.getBaseUrl(request));
                } catch (err) {
                    const errorMessage = `Unable to authenticate - could not obtain grant code. ${err}`;
                    log(['error', 'keycloak'], errorMessage);
                    return keycloak.answer(reply).representation(Boom.forbidden(errorMessage));
                }
            }
        },
        config: {
            auth: false,
            cors: {
                origin: keycloak.config.corsOrigin
            }
        }
    });
};

const registerBackChannelLogoutRoute = (keycloak) => {
    keycloak.server.route({
        path: '/k_logout',
        method: 'POST',
        handler: async (request, reply) => {
            keycloak.server.log(['debug', 'keycloak'], 'Back-channel logout');

            const logoutToken = new Token(request.payload);

            try {
                await keycloak.actionTokenVerifier.verify(logoutToken, {
                    action: 'LOGOUT',
                    resource: keycloak.config.clientId
                });
            } catch (ex) {
                const message = `Invalid token has been provided. ${ex}`;
                keycloak.server.log(['warn', 'keycloak'], message);
                return keycloak.answer(reply).representation(Boom.badRequest(message));
            }

            const sessionIds = logoutToken.content.adapterSessionIds || [];
            try {
                await Promise.all(sessionIds.map(sessionId => keycloak.server.yar.revoke(sessionId)));
            } catch (ex) {
                const message = `An error occurred during dropping sessions. ${ex}`;
                keycloak.server.log(['warn', 'keycloak'], message);
                return keycloak.answer(reply).representation(Boom.notImplemented(message));
            }

            return keycloak.answer(reply).representation('Successfully dropped all user\'s sessions.');
        },
        config: {
            auth: false
        }
    });
};

const registerLogoutRoute = (keycloak) => {
    keycloak.server.route({
        path: keycloak.config.logoutUrl,
        method: 'GET',
        handler(request, reply) {
            keycloak.server.log(['debug', 'keycloak'], 'Signing out');
            const grantStore = keycloak.getGrantStoreByName('session');
            grantStore.clearGrant(request);
            const redirectUrl = keycloak.getBaseUrl(request);
            const logoutUrl = keycloak.getLogoutUrl({redirectUrl});
            return reply.redirect(logoutUrl);
        },
        config: {
            auth: false,
            cors: {
                origin: keycloak.config.corsOrigin
            }
        }
    });
};

/* This is a plugin registration backward-compatible with Hapijs v14+ */
const register = (server, options, next) => {
    const adapter = new KeycloakAdapter(server, options);
    adapter.register();
    if (next) {
        next();
    }
};
register.attributes = {pkg};
module.exports = {
    register,
    pkg,
    KeycloakAdapter
};
