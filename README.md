# sanitize

Untrusted strings in, something safe to store out.

Every method takes a string you did not write and returns either a clean value
or `''`. Always `''` — never null, never an exception — so every call site is
the same shape and nobody has to remember which validator throws.

```bash
composer require sugarcommerce/sanitize
```

Zero dependencies.

## Use

```php
use SugarCommerce\Sanitize\Input;

Input::clean_text( $value, 120 );           // control characters out, whitespace collapsed
Input::email( ' Jordan@EXAMPLE.COM ' );     // 'Jordan@example.com', or ''
Input::mask_email( 'jordan@example.com' );  // 'jo****@example.com'
Input::url( $value );                       // http(s) only, or ''
Input::prefixed_id( $value, 'acct' );       // 'acct_1A2b3C', or ''
Input::hex( $value, 64 );                   // lower-cased, exact length, or ''
Input::int( $_GET['page'] ?? 1, 1, 10_000, 1 );
Input::int_or_null( $_POST['expiry'] ?? null, 1, 3650 );   // null when unset
Input::hex_colour( $value );                               // '#6d28d9', or ''
Input::one_of( $_GET['sort'] ?? '', $sortable, 'created_at' );
```

`clean_text()`, `email()`, `url()`, `hex_colour()` and `int_or_null()` take
`mixed`, not `string`. That is deliberate: untrusted input is not a string
until you have checked, and a caller writing `(string) $input['name']` on
something that turns out to be an array gets `"Array"` and a warning — and
`"Array"` is a value that reaches a database.

This is not an escaper. Escaping belongs at the point of output, where the
context is known; a class that does both produces double-escaped text the first
time somebody uses them together.

## What each one is actually for

**`clean_text()`** strips more than control characters. It also removes the
Unicode used for display spoofing — zero-width joiners, the byte-order mark,
and the bidirectional overrides that make an uploaded `exe.txt` render as
`txt.exe` in a file listing. That is a real attack on anything that shows a
user-supplied filename, not a theoretical one.

Truncation is by characters, not bytes, so a limit of 120 does not cut a
multi-byte character in half and leave invalid UTF-8 in the database.

**`email()`** lower-cases the domain and leaves the local part alone. RFC 5321
says the local part is case-sensitive; lower-casing the whole address is the
common shortcut, and the mail that eventually bounces is nobody's fault but
yours.

**`mask_email()`** is for lists and logs. `jo****@example.com` is enough to
recognise an address you already know and not enough to harvest one you do not.
Show the full value on one screen, and log the reveal.

**`url()`** rejects every scheme but http and https. `javascript:` and `data:`
are the ones that matter — both become script execution the moment the value
reaches an `href`, and `filter_var()` on its own accepts them happily.

**`prefixed_id()`** matches the `prefix_alphanumeric` shape most object APIs
use: Stripe's `acct_`, `price_`, `cs_`, and plenty of others. Checking the
prefix as well as the alphabet is what stops a customer id being passed where
an account id was meant and silently looking up nothing.

**`hex_colour()`** takes six digits only, lower-cased. The three-digit form is
valid CSS but doubles the shapes anything downstream has to handle, and a
caller comparing stored values would have `#fff` and `#ffffff` as two different
colours.

It validates rather than escapes, because a colour is usually interpolated into
a `style` attribute where escaping does nothing useful. The dangerous input is
not `<script>` — every escaper catches that — it is
`red;background:url(//evil)`, which survives escaping and is still CSS.

**`int_or_null()`** is for the settings that mean "no limit" when unset: a link
that never expires, a download that is not capped. Empty string, null, zero and
nonsense all give `null`, because a select whose "unlimited" option has an empty
value and a form that posts `0` are both saying the same thing. Distinct from
`int()`, which always returns a number — the difference is whether "not set" is
a value you need to keep.

**`int()`** clamps rather than rejecting. A page number of 10,000,000 is
somebody fuzzing, and answering with the last page is a better response than an
error that confirms the query ran.

**`one_of()`** is the allow-list form — and the only validation that works for
a value that reaches SQL as an identifier rather than a parameter. A sort
column or a table alias cannot be bound, so the list of permitted ones has to
be written in code and everything else discarded.

```php
$sort = Input::one_of( $_GET['sort'] ?? '', array( 'created_at', 'name' ), 'created_at' );

$db->all( "SELECT * FROM things ORDER BY {$sort} DESC" );
```

## Testing

```bash
composer test
```

## License

GPL-2.0-or-later
