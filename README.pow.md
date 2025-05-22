# The `pow` credentials checker

The `pow` credentials checker is a special case: It provides a guest login
with fixed username and password, but for using it, it requires the client's
browser to solve a cryptographic puzzle.

The username and password it accepts can be configured, both default to
`guest`. Also the difficulty of the puzzle can be configured, it defaults to
`4`.

## How it works ...

The idea for the cryptographic puzzle is taken from the
[Anubis](https://github.com/TecharoHQ/anubis) project. It works by giving the
client browser some pseudo-random challenge string and requiring it to find a
nonce so that the concatenation of the challenge and the nonce produces an
sha256 hash with a certain number of leading zeros. The difficulty configures
how many leading zeros this hash must have.

This means the client has to calculate *lots* of sha256 hashes to find an
appropriate nonce, because the hashing function cannot be inverted. The
server on the other hand only has to create a single sha256 hash to verify
that the nonce supplied by the client indeed qualifies.

Note this requires users to use a modern full-featured web browser, because
solving the puzzle requires the `SubtleCrypto` and `Web Worker` Javascript
APIs. But it ensures to keep crawler/scraper bots out (solving the puzzles
would be too expensive for them), while human visitors can use the guest login
with just an instant of waiting.

## What's different compared to Anubis?

* Anubis acts as a reverse proxy itself, while swad is designed for usage with
  e.g. nginx and only handles the login procedure and a little authentication
  request it gets from the proxy.
* Anubis "only" provides the crypto challenge, while swad offers logins using
  different methods. On the other hand, Anubis offers a fancy UI with nice
  pictures, explanations, even a progress bar, while swad's `pow` checker does
  it pretty much "bare bones", just showing a simple spinner while the client
  solves the puzzle.
* The challenge is constructed in a slightly different way. Swad calculates an
  expiration timestamp for the challenge 5 minutes in the future, solutions
  POSTed later are not accepted any more. It adds this timestamp, the real
  remote address (as obtained from proxy headers), the user agent string and
  all "Accept" headers to a buffer that's then hashed to a hex string for
  creating the challenge. The expiration timestamp is sent back from the
  client together with the solving nonce, so the exact same challenge can be
  constructed again for verification.
* Anubis issues a signed JWT on success, swad works with a server-side session
  identified by a random session ID. The advantage of the JWT is not requiring
  any server-side state and therefore saving server RAM, the advantage of the
  session is fewer work for verification and fewer extra data added to the
  traffic.

## How to let visitors know of the guest login?

You can override the login template. On installation, swad installs its
default templates as samples into `${prefix}/etc/swad`. So you will find a
file `login.html.sample` there.

Copy this file to `login.html` (or to `login.foobar.html` if it should only be
displayed for the realm `foobar`) and add your message.

You could even add a "guest login button", e.g. by adding the following below
the existing login form:

```Html
    <h2>Guest access</h2>
    <p>You may have your browser solve a<br>
    cryptographic puzzle to get guest access:</p>
    <form action="%%SELF%%" method="post">
      <input type="hidden" name="realm" value="%%REALM%%">
      <input type="hidden" name="rdr" value="%%RDR%%">
      <input type="hidden" name="user" value="guest">
      <input type="hidden" name="pw" value="guest">
      <input type="hidden" name="login" value="login">
      <input type="submit" name="enter" value="Solve!">
    </form>
```

Or, if you don't want "regular" logins for a specific realm at all, you could
just replace the `<body>` content of the corresponding template with a form
only containing the hidden inputs as above, and add some Javascript to
auto-submit it on load.

