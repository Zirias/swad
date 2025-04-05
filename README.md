# swad - Simple Web Authentication Daemon

`swad` provides a http service for cookie authentication with a HTML login
form. The intended usage is to put it behind a reverse proxy that can do
sub-requests for authentication, like nginx' `auth_request` module.

## Features

* Configurable credential checker modules (for username + password)
* Configurable authentication realms, with a stack of credential checkers
  to try for that realm
* Optional HTTPS support
* Protection against CSRF (Cross-site request forgery)
* Redirects back to the page that triggered the login

### Available credential checker modules

* `pam`: Use PAM with a configurable service name to authenticate. This
  module uses a small child process to perform PAM authentication, which
  does not drop privileges. So, when `swad` is started as root, PAM
  authentication will also work for PAM modules which require root
  privileges, like `pam_unix.so`.

More modules are planned.

## How it works

`swad` offers cookie authentication using a randomly generated session cookie
and storing all other state server-side in RAM. It exposes two endpoints, one
for checking authentication and one for performing logins. Both endpoints
accept two parametes, either from the query string, or from a custom header
which takes precedence if both are present:

* The realm name. If this is missing, a default name of `SWAD` is assumed.
  - Query string: `realm`
  - Header: `X-SWAD-Realm`
* The redirect uri. This is used for the redirect after successful login. If
  missing, a default value of `/` is assumed.
  - Query string: `rdr`
  - Header: `X-SWAD-Rdr`

Both parameters are stored in the session. They are deleted when a new value
is provided, or when an actual login is performed. For security reasons,
the login endpoint ignores these parameters for the actual login request, but
accepts them for rendering the login form.

### Endpoint details

* `/`, method `GET`: Check current authentication. Accepts an additional
  parameter for the route to the login endpoint in the custom header
  `X-SWAD-login`. If missing, a default of `/login` is used.
  - response `200`: Returned if the user is authenticated for the given realm.
    Returns a `text/plain` document containing the user name and, if
    available, the user's real name in a second line.
  - response `403`: Returned if the user is not yet authenticated for the
    given realm. Returns a `text/html` document with a redirect to the login
    route.

* `/login`, methods `GET` and `POST`: Perform login and redirect back.
  - `GET`: Show the login form. Accepts the standard parameters descibed
    above.
    + response `200`: Returns a `text/plain` document with a HTML login form
      and the requested realm shown in the title.
  - `POST`: Perform login. Ignores the standard parameters described above.
    + response `303`: Returned on failed login, redirects back to the login
      form, keeping the user name and adding an error message.
    + response `200`: Returned on successful login. Returns a `text/html`
      document with a redirect as given by `rdr`/`X-SWAD-Rdr`.

## Example usage with nginx

The following example shows how to configure an nginx reverse proxy to add
authentication to a path `/secret`, which is proxied to an internal server
`internal.example.com` without authentication. For this example, `swad` is
assumed to run on `swad.example.com` and configured for TLS on port `8443`
and an authentication realm called `Secret`. For details how to configure
`swad`, see the example configuration file `swad.conf.sample`.

`nginx.conf` snippet:

```Nginx
location @auth403 {
    add_header Set-Cookie $auth_cookie;
    return 303 /login;
}

location /secret {
    auth_request /auth;
    set $auth_realm Secret;
    auth_request_set $auth_cookie $upstream_http_set_cookie;
    proxy_pass http://internal.example.com;
    proxy_http_version 1.1;
    proxy_hide_header ETag;
    proxy_hide_header Last-Modified;
    add_header Cache-Control "no-cache no-store must-revalidate";
    add_header Set-Cookie $auth_cookie;
    proxy_intercept_errors on;
    error_page 403 @auth403;
}

location = /login {
    proxy_pass https://swad.example.com:8443;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location = /auth {
    proxy_pass https://swad.example.com:8443/;
    proxy_http_version 1.1;
    proxy_method GET;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-SWAD-Realm $auth_realm;
    proxy_set_header X-SWAD-Rdr $request_uri;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Note the `proxy_pass` for `/auth` uses a trailing slash, so the proxied
request always goes to the `/` endpoint of `swad`. For `/login`, no path
in `proxy_pass` is needed because the external route is exatly the same
as the internal one. With that configuration, we also don't need to use
`X-SWAD-Login`.

Some key aspects to make this work are:

* We make sure to always pass `Set-Cookie` headers from `swad`. Otherwise,
  `swad` couldn't correctly establish the user session.
* We always pass the realm and redirect uri with every request checking
  authentication. This makes sure a login will use whatever was requested
  last when authentication failed.
* We provide a redirect to login in nginx, via `proxy_intercept_errors` and
  `@auth403` for the error document. This is unfortunately necessery,
  because nginx' `auth_request` can't pass a body from a `403` response, which
  would already contain the required redirect.
* We make sure to force the `GET` method and no request body for auth
  requests. `swad`'s authentication endpoint only supports `GET`.

A few aspects of this config aren't strictly required, but make things nicer:

* We always add an `X-Forwarded-For` header, enabling `swad` to log the real
  address of clients doing authentication and login.
* We disable any caching for the `/secret` route, so e.g. an expired `swad`
  session is discovered immediately and performs a redirect to `/login`.

