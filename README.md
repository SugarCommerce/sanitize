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
Input::one_of( $_GET['sort'] ?? '', $sortable, 'created_at' );
```

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
