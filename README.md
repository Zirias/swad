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
* Configurable rate-limit for creating new sessions (protect against DoS)
* Configurable rate-limit for failed logins per session, realm and user name
  (protect against brute-force)
* Redirects back to the page that triggered the login

### Available credential checker modules

* `exec`: Execute an external tool to check the credentials. The tool is
  called with the user name as the single argument, and the password is
  written to its standard input. An exit code of 0 indicates successful login,
  any non-zero exit code indicates failure. The tool may write a "real name"
  to its standard output.
* `file`: Use a password file partially compatible with Apache's `.htpasswd`
  files. Supports only `bcrypt` hashes in the `$2a$`, `$2b$` and `$2y$`
  flavors. A user's real name may be appended to a line in this file after
  another colon.
* `pam`: Use PAM with a configurable service name to authenticate. This
  module uses a small child process to perform PAM authentication, which
  does not drop privileges. So, when `swad` is started as root, PAM
  authentication will also work for PAM modules which require root
  privileges, like `pam_unix.so`.

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

* `/`, method `GET`: Check current authentication.
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
    proxy_pass https://swad.example.com:8443/login;
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
request always goes to the `/` endpoint of `swad`. For `/login`, we map
the request to the same path in the backend, *without* a trailing slash,
so sub-paths are also passed correctly. This is required to find e.g. the
stylesheet for the login form. We could use a different route by
configuring `login_route` in `swad.conf`.

Some key aspects to make this work are:

* We make sure to always pass `Set-Cookie` headers from `swad`. Otherwise,
  `swad` couldn't correctly establish the user session.
* We always pass the realm and redirect uri with every request checking
  authentication. This makes sure a login will use whatever was requested
  last when authentication failed.
* We always add an `X-Forwarded-For` header, so `swad` knows the real remote
  address and can base its rate limits on this information, as well as log it.
* We provide a redirect to login in nginx, via `proxy_intercept_errors` and
  `@auth403` for the error document. This is unfortunately necessery,
  because nginx' `auth_request` can't pass a body from a `403` response, which
  would already contain the required redirect.
* We make sure to force the `GET` method and no request body for auth
  requests. `swad`'s authentication endpoint only supports `GET`.

A few settings aren't strictly required, but make things nicer: We disable any
caching for the `/secret` route, so e.g. an expired `swad` session is
discovered immediately and performs a redirect to `/login`.

Here's a minimal `swad.conf` example to match this nginx configuration:

```ini
user = swad		; use some unprivileged user here to drop privileges

[server]
port = 8443
tls = on
tls_cert_file = /usr/local/etc/swad/swad.crt
tls_key_file = /usr/local/etc/swad/swad.key
trusted_proxies = 1
trusted_header = xfwd

[checkers]
pam_swad = pam:swad

[realms]
Secret = pam_swad
```

## Building

To obtain the source from git, make sure to include submodules, e.g. with the
`--recurse-submodules` option to `git clone`. Release tarballs will include
everything needed for building.

Dependencies:

* A C compiler understanding GNU commandline options and the C11 standard
  (GNU GCC and LLVM clang work fine)
* GNU make
* OpenSSL, or a compatible implementation like LibreSSL, when building with
  bundled poser and TLS enabled
* PAM (libpam and headers) when building with the PAM credentials checker

To build and install swad, you can simply type

    make
    make install

If your default `make` utility is not GNU make (like e.g. on a BSD system),
install GNU make first and type `gmake` instead of `make`.

### Build options

Options can be given as variables in each make invocation, e.g. like this:

    make FOO=yes
    make FOO=yes install

Alternatively, they can be saved and are then used automatically, like this:

    make FOO=on config
    make
    make install

The following build options are available:

* `BUNDLED_POSER` (bool): Uses the bundled poser lib and links it statically.
  When disabled, poser must be installed and will be linked as a shared
  library.

  Default: `on`.

* `WITH_POSER_TLS` (bool, only for `BUNDLED_POSER=on`): Build with TLS
  support, required for https.

  Default: `on`.

* `OPENSSLINC`/`OPENSSLLIB` (paths, only for `WITH_POSER_TLS=on`): Override
  base paths to OpenSSL includes and libraries.

  Default: Obtain from pkg-config.

* `WITH_POSER_POLL` (bool, only for `BUNDLED_POSER=on`): Use `poll()` instead
  of `select()` for obtaining events when neither `kqueue()` nor `epoll()`
  are available. With `poll()`, there is no hard limit on concurrent clients,
  but performance may scale even worse than with `select()` because more data
  has to be passed in and out of the kernel for every call.

  Default: `off`

* `POSER_FD_SETSIZE` (number, only for `BUNDLED_POSER=on`): When `select()` is
  used for obtaining events, try to configure it for allowing this many
  concurrent file descriptors. Not all systems allow doing this, they will
  typically have a hardcoded limit of `1024`.

  Default: `4096`

* `WITH_POSER_EPOLL` (bool, only for `BUNDLED_POSER=on`): Require `epoll()`,
  fail the build if `epoll()` is not available.

  Default: `off`

* `WITHOUT_POSER_EPOLL` (bool, only for `BUDNLED_POSER=on`): Never use
  `epoll()` even if detected.

  Default: `off`

* `WITH_POSER_KQUEUE` (bool, only for `BUNDLED_POSER=on`): Require `kqueue()`,
  fail the build if `kqueue()` is not available.

  Default: `off`

* `WITHOUT_POSER_KQUEUE` (bool, only for `BUDNLED_POSER=on`): Never use
  `kqueue()` even if detected.

  Default: `off`

* `WITH_MAN` (bool): Build and install manpages.

  Default: `on`

* `MANFMT` (string): The format for the manpages. Valid values are `mdoc` for
  BSD-style mandoc format, or `man` for the classic format based on the man
  macro package for troff.

  Default: `mdoc` if the OS name contains "BSD", `man` otherwise

* `CRED_EXEC` (bool): Build with the "exec" credentials checker.

  Default: `on`

* `CRED_FILE` (bool): Build with the "file" credentials checker. Also build
  and install the swadpw(1) tool.

  Default: `on`

* `CRED_PAM` (bool): Build with the "pam" credentials checker. Also build and
  install the required pam helper binary.

  Default: `on`

### Advanced build configuration

Swad uses a custom build system called `zimk`, which is included as a git
submodule. This offers a lot of generic build configuration possibilities.

For a list of all configuration variables, most of which can be overridden and
saved with `make config` as described above, type

    make showconfig

This will also show the fully expanded value of all available variables.

There are also a few special variables which are not saved with the
configuration:

* `DESTDIR` (string): Only used during `make install`, the value of `DESTDIR`
  is prepended to the path of every installed file.
* `PREFIX` (string): Convenience equivalent to the configuration variable
  `prefix` (defaulting to `/usr/local`), for compatibility with other build
  systems.
* `V` (0/1) and `COLORS` (0/1): These override *verbose* and *colored*
  output of the build. By default, verbose output is chosen when the output
  doesn't go to a terminal, colored output is only chosen when the output goes
  to a terminal with color support.

