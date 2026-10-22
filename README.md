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
Input::multiline( $note, 1_000, 20 );       // paragraphs kept, runs of blanks collapsed
Input::truncate( $html, 20_000 );          // trimmed and capped, inside untouched
Input::email( ' Jordan@EXAMPLE.COM ' );     // 'Jordan@example.com', or ''
Input::mask_email( 'jordan@example.com' );  // 'jo****@example.com'
Input::url( $value );                       // http(s) only, or ''
Input::prefixed_id( $value, 'acct' );       // 'acct_1A2b3C', or ''
Input::hex( $value, 64 );                   // lower-cased, exact length, or ''
Input::int( $_GET['page'] ?? 1, 1, 10_000, 1 );
Input::int_or_null( $_POST['expiry'] ?? null, 1, 3650 );   // null when unset
Input::hex_colour( $value );                               // '#6d28d9', or ''
Input::one_of( $_GET['sort'] ?? '', $sortable, 'created_at' );

// Lists and switches (1.3.0)
Input::prefixed_ids( $_POST['price'] ?? [], 'price', 20 );  // valid ids, once each, in order
Input::list( "a, b\nc" );                                   // ['a', 'b', 'c']
Input::bool( $settings['enabled'] ?? null );                // strict: 'false' is false
Input::origin( 'https://Shop.example.com/x' );              // 'https://shop.example.com', or ''
Input::mask( $access_key );                                 // 'AKIA…WXYZ'
Input::number_list( $peaks, 0.0, 1.0, 4_000, 2 );           // clamped, or null
```

`clean_text()`, `multiline()`, `email()`, `url()`, `hex_colour()` and
`int_or_null()` take
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
the soft hyphen and invisible fillers, the Unicode tag block, and every
bidirectional override and isolate, the controls that make an uploaded
`exe.txt` render as `txt.exe` in a file listing. That is a real attack on
anything that shows a user-supplied filename, not a theoretical one.

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

**`multiline()`** is `clean_text()` for anything somebody typed into a
textarea. `clean_text()` collapses every run of whitespace to one space, which
turns their paragraphs into one long line. This keeps the line breaks, collapses
runs of blank lines to one, normalises `\r\n` and a lone `\r` to `\n` so the
same note stores identically whatever it was typed on, and can cap the number
of lines as well as the number of characters.

**`truncate()`** is `clean_text()`'s counterpart for values that are not prose
— an HTML body, a template — where collapsing runs of whitespace would change
what was written. It trims the ends, caps the length in characters rather than
bytes, and leaves the middle alone.

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

**`prefixed_ids()`** is `prefixed_id()` for a list — the prices in a cart,
the products on a shelf. Entries that do not match are dropped rather than
failing the list, duplicates go, and the caller's order is kept. The cap is on
how many entries are *read*, so a list padded with ten thousand values costs no
more than one at the cap.

**`list()`** reads a list somebody typed into one field — commas, spaces, new
lines, or all three — or an array. Entries are trimmed, empties and duplicates
dropped, order kept. It does not judge the entries: pass each through the
validator for what it should be.

**`bool()`** is strict about switches. `true`, `1`, `"1"`, `"true"`, `"on"`
and `"yes"` are on; their opposites are off; anything else is the default.
`(bool) "false"` is `true`, which is how a setting ends up doing the opposite of
what somebody chose.

**`origin()`** reduces a URL to scheme, host and port — what a browser's
`Origin` header is compared with. https only unless you pass `false`; a value
carrying credentials (`https://user@host`) or an odd host is refused.

**`mask()`** shortens a credential or bucket name to what recognises it: four
characters of each end from sixteen up, three and two from ten, one character
of anything shorter.

**`number_list()`** is for numbers a browser computed and sent back — a
waveform's peaks. All or nothing: one entry that is not a JSON number means the
list is not what the page drew, so the answer is `null` rather than the rest.

## Testing

```bash
composer test
```

75 tests: every method's happy path, its refusals, and the non-scalar input a
form or JSON body can carry where a string was expected.

## License

GPL-2.0-or-later
