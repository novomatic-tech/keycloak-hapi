# keycloak-hapi

This repository consist of a [HapiJS](https://hapijs.com/) auth plugin 
which delegates authorization concerns to the [Keycloak](https://www.keycloak.org/) server.

## Features

This package:

- Defines a `keycloak` [Hapijs auth scheme](https://hapijs.com/tutorials/auth) so that it can be used as follows:

  ```javascript
  server.auth.strategy('keycloak', 'keycloak');
  server.auth.default('keycloak');
  server.route({
      method: ['GET'],
      path: '/restricted',
      handler(request, reply) {
          return `Hello, ${request.auth.credentials.name}!`; // this will return user's full name.
      },
      options: {
         auth: {
              access: {
                  scope: ['view-reports', 'manage-reports'] // Optionally, these are required Keycloak roles for this endpoint.
              }
          }
      }
  });
  ```

- Exposes 3 endpoints intended to be used with frontend web apps:

  - Login endpoint (`/sso/login`) which handles OAuth2.0's Authorization Code redirection flow.
  - Logout endpoint (`/sso/logout`) which handles sign out procedure.
  - Principal endpoint (`/api/principal`) which gives access to resource owner's data (such as its name, access token, ID token, change password URL, logout URL etc.)

## Install

```bash
$ npm install keycloak-hapi --save
```

## Usage

```javascript
const server = new Hapi.Server();

try {
  /*
   * The package uses yar for session management so this bit is required 
   * if you're writing a frontend web app (bearerOnly = false).
   */
  await server.register({
      plugin: require('yar'),
      options: {
          storeBlank: false,
          name: 'kc_session',
          maxCookieSize: 0,
          cookieOptions: {
              password: 'the-password-must-be-at-least-32-characters-long',
              isSecure: false // use true for production (https).
          }
      }
  });
  
  await server.register({
      plugin: require('keycloak-hapi'),
      options: {
          serverUrl: 'http://localhost:8080/auth',
          realm: 'master',
          clientId: 'my-app',
          clientSecret: '6a0dd495-09bc-4ed1-87a2-3367bb75b05d',
          bearerOnly: false // set it to true if you're writing a resource server (REST API).
      }
  });
  
  server.auth.strategy('keycloak', 'keycloak');
  server.auth.default('keycloak');
  
} catch(err) {
    console.error(err);
}

await server.start();
```

## Configuration

The following plugin `options` are available to be set:

Parameter | Description | Default
--- | --- | ---
`serverUrl` | The base URL of the Keycloak server. All other Keycloak pages and REST service endpoints are derived from this. It is usually of the form https://host:port/auth. This is **REQUIRED**. | 
`realm` | Name of the realm. This is **REQUIRED**. | 
`clientId` |  The client-id of the application. Each application has a client-id that is used to identify the application. This is **REQUIRED**. | 
`clientSecret` | The client secret of the application. Each application that uses OAuth's Authorization Code flow has one assigned. This is **REQUIRED**. | 
`bearerOnly` | A value indicating whether a bearer-only authorization should be performed. Set it to `true` only if you're writing a backend (a REST API) | `false`
`realmPublicKey` | PEM format of the realm public key. You can obtain this from the administration console. This is OPTIONAL and will be fetched directly from the server when not defined. | `undefined`
`minTimeBetweenJwksRequests` | Amount of time, in seconds, specifying minimum interval between two requests to Keycloak to retrieve new public keys. | `10`
`loginUrl` | An URL of the endpoint responsible for obtaining OAuth2.0's Authorization Code grant. It is exposed only if `bearerOnly` is set to false. | `/sso/login`
`logoutUrl` | An URL the endpoint responsible for handling logout procedure. It is exposed only if `bearerOnly` is set to false. | `/sso/logout` 
`principalUrl` | An URL of the endpoint exposing resource owner's data (such as its name, ID token, access token etc.). Use `null` in order not to expose this endpoint at all. | `/api/principal`
`principalConversion` | A function which alters principal representation exposed by `principalUrl` endpoint before it's sent in a response. Define this function if you don't want for example an access token to be exposed. | `undefined` (no conversion)
`principalNameAttribute` | An access/ID token attribute which will be used as the principal name (user name). It will fallback to *sub* token attribute in case the *principalNameAttribute* is not present. Possible values are *sub*, *preferred_username*, *email*, *name*. | `name`
`corsOrigin` | CORS for the `loginUrl` and `logoutUrl` endpoints. In production, only Keycloak server's FQDN should be defined here. | `['*']`
`shouldRedirectUnauthenticated` | A function used for not authenticated users. It takes a `request` as a parameter and should return: - `false` - if the endpoint should reply with an HTTP 401 right away. - `true` - if the user should be redirected to the Keycloak login page. By default, `401` will be returned when `bearerOnly` is set to `true`, route auth mode is set to `optional` or `try`, if we're accessing `/api/*` route or request was AJAX (it contains header `x-requested-with` set to `XMLHttpRequest`). |
`basePath` | A base path to use if app is running behind a reverse proxy. This path will be inserted in redirect URIs. It could be useful when proxy changes the base path.  | `undefined`
`baseUrl` | A base URL to use if app is running behind a reverse proxy where we can't rely on `x-forwarded-host` and `x-forwarded-proto` headers. When set, request headers and `basePath` (if set) are ignored. Note that `server.realm.modifiers.route.prefix` is appended to `baseUrl` when base URL is calculated. This URL will be inserted in redirect URIs. | `undefined`
`redirectUris` | List of valid URI pattern a browser can redirect to after a successful login. Simple wildcards are allowed such as `http://example.com/*`. URIs are based on URLPattern API. Relative path can be specified too such as `/my/relative/path/*`. Relative paths are relative to the client base URL and it is requierd to be specified in configuration. | `['*']`

## Examples

See https://github.com/novomatic-tech/keycloak-examples/tree/master/app-web-nodejs

## Yar compatibility

This package requires the [yar](https://www.npmjs.com/package/yar) library at least in version ``9.1.0``. 
To get compatibility with version ``8``, use [yar8](https://www.npmjs.com/package/yar8).