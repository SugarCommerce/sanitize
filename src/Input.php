<?php
/**
 * Input cleaning and validation.
 *
 * @package SugarCommerce\Sanitize
 */

declare( strict_types=1 );

namespace SugarCommerce\Sanitize;

/**
 * Class Input
 *
 * Every method takes an untrusted string and returns something safe to store,
 * or an empty string the caller must handle. Nothing here escapes for output —
 * that is the view's job, and a class that does both produces double-escaped
 * text the first time somebody uses them together.
 *
 * The empty string rather than null or an exception, consistently. A validator
 * that sometimes throws and sometimes returns null makes every call site a
 * decision; one that always answers the same way makes them all the same
 * shape: `if ( '' === $email )`.
 *
 * @since 1.0.0
 */
final class Input {

	/**
	 * Control characters: C0 except tab, newline and carriage return, DEL,
	 * and C1.
	 *
	 * @since 1.4.0
	 */
	private const string CONTROL = '/[\x{00}-\x{08}\x{0B}\x{0C}\x{0E}-\x{1F}\x{7F}-\x{9F}]/u';

	/**
	 * Characters that change how text displays without being seen.
	 *
	 * Zero-width spaces and joiners, the soft hyphen and the invisible
	 * fillers; every bidirectional control — the embeddings and overrides
	 * (U+202A–U+202E) and the isolates (U+2066–U+2069) that "Trojan Source"
	 * used, plus the Arabic letter mark; invisible operators; the
	 * interlinear annotation marks; the byte-order mark; and the Unicode tag
	 * block, which renders as nothing and can carry a whole hidden sentence.
	 *
	 * @since 1.4.0
	 */
	private const string INVISIBLE = '/[\x{00AD}\x{034F}\x{061C}\x{115F}\x{1160}\x{17B4}\x{17B5}\x{180E}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{206F}\x{3164}\x{FEFF}\x{FFA0}\x{FFF9}-\x{FFFB}\x{E0000}-\x{E007F}]/u';

	/**
	 * Strip control characters and collapse whitespace.
	 *
	 * Removes the C0 and C1 ranges except tab, newline and carriage return,
	 * plus the Unicode characters used for display spoofing: zero-width
	 * joiners, bidirectional overrides and isolates, the byte-order mark and
	 * the rest of {@see self::INVISIBLE}. A filename containing U+202E
	 * renders right-to-left and can make `exe.txt` look like `txt.exe`,
	 * which is a real upload attack and not a theoretical one.
	 *
	 * Text that is not valid UTF-8 comes back as '': there is no safe way to
	 * guess what it was meant to say.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value      Untrusted text. Anything that is not a scalar
	 *                          becomes '', because a caller casting (string)
	 *                          on an array gets "Array" and a warning, and
	 *                          "Array" is a value that reaches a database.
	 * @param int   $max_length Truncation point. 0 for no limit.
	 *
	 * @return string
	 */
	public static function clean_text( mixed $value, int $max_length = 0 ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$value = self::strip( (string) $value );
		$value = trim( preg_replace( '/\s+/u', ' ', $value ) ?? '' );

		if ( $max_length > 0 && mb_strlen( $value ) > $max_length ) {
			$value = mb_substr( $value, 0, $max_length );
		}

		return $value;
	}

	/**
	 * Text that is allowed to have lines in it.
	 *
	 * clean_text() collapses every run of whitespace to one space, which is
	 * right for a name and wrong for a note somebody typed into a textarea:
	 * their paragraphs come back as one long line.
	 *
	 * This keeps single newlines, collapses runs of blank lines to one, and
	 * still strips the control characters and direction overrides clean_text()
	 * strips. Carriage returns are normalised away first, so a note typed on
	 * Windows and the same note typed on a Mac store identically.
	 *
	 * @since 1.2.0
	 *
	 * @param mixed $value      Untrusted text.
	 * @param int   $max_length Truncation point. 0 for no limit.
	 * @param int   $max_lines  Lines to keep. 0 for no limit.
	 *
	 * @return string
	 */
	public static function multiline( mixed $value, int $max_length = 0, int $max_lines = 0 ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$value = self::strip( (string) $value );

		// Both \r\n and a lone \r become \n before anything counts lines.
		$value = str_replace( array( "\r\n", "\r" ), "\n", $value );

		// Horizontal whitespace only: a run of spaces and tabs collapses, a
		// newline survives.
		$value = preg_replace( '/[^\S\n]+/u', ' ', $value ) ?? '';

		// Three blank lines and one say the same thing to a reader.
		$value = preg_replace( '/\n{3,}/', "\n\n", $value ) ?? '';

		// A space before a newline is invisible, and would otherwise count
		// towards the length.
		$value = preg_replace( '/ +\n/', "\n", $value ) ?? '';
		$value = trim( $value );

		if ( $max_lines > 0 ) {
			$value = implode( "\n", array_slice( explode( "\n", $value ), 0, $max_lines ) );
		}

		if ( $max_length > 0 && mb_strlen( $value ) > $max_length ) {
			$value = rtrim( mb_substr( $value, 0, $max_length ) );
		}

		return $value;
	}

	/**
	 * A valid, normalised email address, or ''.
	 *
	 * The local part keeps its case because RFC 5321 says it is significant;
	 * the domain is lower-cased because it is not. Normalising the whole
	 * thing to lower case is the common shortcut and it is wrong — there are
	 * mail servers that treat the local part as case-sensitive, and the
	 * bounce is nobody's fault but yours.
	 *
	 * Longer than 254 characters is refused, not shortened: the first 254
	 * characters of something are a different address, and possibly a valid
	 * one belonging to somebody else.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value Untrusted address.
	 *
	 * @return string The address, or '' when it is not one.
	 */
	public static function email( mixed $value ): string {
		$value = self::clean_text( $value );

		if ( ! str_contains( $value, '@' ) || mb_strlen( $value ) > 254 ) {
			return '';
		}

		[ $local, $domain ] = explode( '@', $value, 2 );
		$value              = $local . '@' . mb_strtolower( $domain );

		return false === filter_var( $value, FILTER_VALIDATE_EMAIL ) ? '' : $value;
	}

	/**
	 * An email with its local part masked, for display in logs and lists.
	 *
	 * `jordan@example.com` becomes `jo****@example.com`. Enough to recognise
	 * an address you already know, not enough to harvest one you do not.
	 *
	 * The first two characters of the local part stay (one, when that is
	 * all there is) and the rest are masked, with at least `$min_hidden`
	 * mask characters whatever the length — at 2, `a@example.com` and
	 * `ab@example.com` both mask to two, so the mask says nothing about how
	 * short the address is. Characters, not bytes: an accented letter is
	 * kept or masked whole, never cut in half.
	 *
	 * `$last_at` splits at the last `@` rather than the first. A domain
	 * cannot contain one and a quoted local part can, so the last is the
	 * right one for a real address; the first is the default only because
	 * it always was. `$keep_invalid` hands back what is not an address — no
	 * `@`, or nothing before it — as it was given rather than '', for a list
	 * cell that should show whatever is stored.
	 *
	 * ```php
	 * Input::mask_email( $email, '•', 2, last_at: true, keep_invalid: true ); // 'ge••••@gmail.com'
	 * ```
	 *
	 * @since 1.0.0
	 * @since 1.5.0 Takes the mask character, a minimum mask length, where to
	 *              split and what to do with a non-address.
	 *
	 * @param string $value        An address.
	 * @param string $mask         What each hidden character becomes.
	 * @param int    $min_hidden   The fewest mask characters shown.
	 * @param bool   $last_at      Split at the last `@` rather than the first.
	 * @param bool   $keep_invalid Return a non-address unchanged, not ''.
	 *
	 * @return string The masked form; '' (or the input, with `$keep_invalid`)
	 *                when the input was not an address.
	 */
	public static function mask_email(
		string $value,
		string $mask = '*',
		int $min_hidden = 1,
		bool $last_at = false,
		bool $keep_invalid = false,
	): string {
		$at = $last_at ? strrpos( $value, '@' ) : strpos( $value, '@' );

		if ( false === $at || ( $keep_invalid && 0 === $at ) ) {
			return $keep_invalid ? $value : '';
		}

		$local = substr( $value, 0, $at );
		$keep  = mb_substr( $local, 0, min( 2, mb_strlen( $local ) ) );

		return $keep . str_repeat( $mask, max( $min_hidden, mb_strlen( $local ) - mb_strlen( $keep ) ) ) . substr( $value, $at );
	}

	/**
	 * An http(s) URL, or ''.
	 *
	 * Other schemes are rejected outright. `javascript:` and `data:` are the
	 * ones that matter — both become script execution the moment the value
	 * reaches an href, and `filter_var` alone accepts them happily.
	 *
	 * Valid is not the same as safe to print: `filter_var` passes
	 * `https://a.example/"><script>`, so the result still has to be escaped
	 * for the attribute it goes into. Longer than 2048 characters is
	 * refused rather than cut, because a cut URL is a different URL.
	 *
	 * With $https_only, `http://` is refused too — for a link the app will
	 * later follow or hand out, where a plain-HTTP one can be rewritten on
	 * the way.
	 *
	 * @since 1.0.0
	 * @since 1.6.0 $https_only.
	 *
	 * @param mixed $value      Untrusted URL.
	 * @param bool  $https_only Refuse http:// as well.
	 *
	 * @return string The URL, or '' when it is not a usable one.
	 */
	public static function url( mixed $value, bool $https_only = false ): string {
		$value  = self::clean_text( $value );
		$scheme = parse_url( $value, PHP_URL_SCHEME );
		$scheme = is_string( $scheme ) ? strtolower( $scheme ) : '';

		if ( mb_strlen( $value ) > 2048 || ! in_array( $scheme, $https_only ? array( 'https' ) : array( 'http', 'https' ), true ) ) {
			return '';
		}

		return false === filter_var( $value, FILTER_VALIDATE_URL ) ? '' : $value;
	}

	/**
	 * A code somebody pasted — an order number, a transaction or tracking
	 * id, a licence key — or ''.
	 *
	 * People copy more than the code: the label in front of it
	 * ("Transaction ID: …"), the quotes around it, straight or curly, and
	 * spaces from wherever it was laid out, including non-breaking and other
	 * Unicode spaces that trim() cannot see. All of that is removed; what is
	 * left has to be 1 to $max characters of A–Z, a–z, 0–9, `_` and `-`.
	 * Case is kept: some systems' codes are case-sensitive.
	 *
	 * The quotes are removed by pattern, not trim(): trim() works on bytes,
	 * and a curly quote shares its first two bytes with other characters —
	 * an em space among them — so trimming one can cut another in half.
	 *
	 *   Input::pasted_code( '“Transaction ID: 9AB 12345”', 64, array( 'Transaction ID' ) ); // '9AB12345'
	 *
	 * @since 1.6.0
	 *
	 * @param mixed         $value  What was pasted.
	 * @param int           $max    Longest code accepted.
	 * @param array<string> $labels Labels that may come before it, followed by
	 *                              a colon. Matched case-insensitively, with
	 *                              any spacing where the label has a space
	 *                              ("Txn ID" matches "TxnID:" and "txn  id :").
	 *
	 * @return string The code, or '' when what is left is not one.
	 *
	 * @throws \InvalidArgumentException When $max is under 1.
	 */
	public static function pasted_code( mixed $value, int $max = 64, array $labels = array() ): string {
		if ( $max < 1 ) {
			throw new \InvalidArgumentException( 'A code has to be allowed at least one character.' );
		}

		if ( ! is_string( $value ) ) {
			return '';
		}

		$code = trim( $value );

		if ( array() !== $labels ) {
			// Longest first, so a label is never cut short by one it begins with.
			usort( $labels, static fn( string $a, string $b ): int => strlen( $b ) <=> strlen( $a ) );

			$names = implode( '|', array_map( static fn( string $label ): string => (string) preg_replace( '/\s+/', '\\s*', preg_quote( trim( $label ), '/' ) ), $labels ) );
			$code  = preg_replace( '/^\s*(?:' . $names . ')\s*:\s*/iu', '', $code ) ?? $code;
		}

		$code = preg_replace( '/^["\'\x{201C}\x{201D}\x{2018}\x{2019}]+|["\'\x{201C}\x{201D}\x{2018}\x{2019}]+$/u', '', $code ) ?? $code;
		$code = preg_replace( '/[\s\p{Z}]+/u', '', $code ) ?? $code;

		return strlen( $code ) <= $max && 1 === preg_match( '/^[A-Za-z0-9_-]+$/D', $code ) ? $code : '';
	}

	/**
	 * An identifier of the form `prefix_alphanumeric`, or ''.
	 *
	 * The shape most object-store APIs use — Stripe's `acct_`, `price_`,
	 * `cs_`; Slack's, Shopify's, plenty of others. Checking the prefix as
	 * well as the alphabet is what stops a caller passing a customer id where
	 * an account id was meant and having it silently look up nothing.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  Untrusted identifier.
	 * @param string $prefix Expected prefix, without the underscore.
	 *
	 * @return string The id, or '' when it does not match.
	 */
	public static function prefixed_id( string $value, string $prefix ): string {
		$value = trim( $value );

		return 1 === preg_match( '/^' . preg_quote( $prefix, '/' ) . '_[A-Za-z0-9_]+$/D', $value ) ? $value : '';
	}

	/**
	 * A hex string of an exact length, or ''. For tokens and digests.
	 *
	 * Lower-cased on the way out, so a value that round-trips through a
	 * database comparison matches whichever case it arrived in.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  Untrusted hex.
	 * @param int    $length Exact number of characters required.
	 *
	 * @return string The lower-cased hex, or ''. Always '' for a length
	 *                below one.
	 */
	public static function hex( string $value, int $length ): string {
		$value = trim( $value );

		return $length > 0 && 1 === preg_match( '/^[a-f0-9]{' . $length . '}$/iD', $value ) ? strtolower( $value ) : '';
	}

	/**
	 * An integer clamped to a range.
	 *
	 * Clamped rather than rejected: a page number of 10,000,000 is somebody
	 * fuzzing, and answering with the last page is a better response than an
	 * error page that tells them the query ran.
	 *
	 * Compared before it is converted, so a number too big for an int —
	 * `1e30` from a JSON body — clamps to the bound it is past instead of
	 * wrapping, or casting to 0 with a warning. NaN is the default.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value   Untrusted value.
	 * @param int   $min     Lower bound.
	 * @param int   $max     Upper bound.
	 * @param int   $default Returned when the value is not numeric at all.
	 *
	 * @return int
	 */
	public static function int( mixed $value, int $min, int $max, int $default = 0 ): int {
		if ( ! is_numeric( $value ) ) {
			return $default;
		}

		if ( is_int( $value ) ) {
			return max( $min, min( $max, $value ) );
		}

		$number = (float) $value;

		if ( is_nan( $number ) ) {
			return $default;
		}

		if ( $number >= $max ) {
			return $max;
		}

		if ( $number <= $min ) {
			return $min;
		}

		return max( $min, min( $max, (int) $number ) );
	}

	/**
	 * Trimmed and capped, with the inside left alone.
	 *
	 * For values that are not prose: a body of HTML, a template, anything
	 * where collapsing runs of whitespace would change what was written.
	 * {@see clean_text()} is the right call for everything else.
	 *
	 * Counts characters rather than bytes, so a limit of 500 cannot cut a
	 * multi-byte character in half and leave invalid UTF-8 in a database.
	 *
	 * @since 1.1.0
	 *
	 * @param mixed $value      Untrusted value.
	 * @param int   $max_length Truncation point. 0 for no limit.
	 *
	 * @return string
	 */
	public static function truncate( mixed $value, int $max_length = 0 ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$value = trim( (string) $value );

		return $max_length > 0 ? mb_substr( $value, 0, $max_length ) : $value;
	}

	/**
	 * A CSS hex colour, or ''.
	 *
	 * Six digits only. The three-digit form is valid CSS but doubles the
	 * number of shapes anything downstream has to handle, and a caller
	 * comparing stored values would then have `#fff` and `#ffffff` as two
	 * different colours.
	 *
	 * Worth validating rather than escaping. A colour is usually interpolated
	 * into a `style` attribute, where escaping does nothing useful — the
	 * dangerous input is not `<script>`, it is `red;background:url(...)`,
	 * which survives every escaper and is still CSS.
	 *
	 * @since 1.1.0
	 *
	 * @param mixed $value Untrusted colour.
	 *
	 * @return string Lower-cased `#rrggbb`, or ''.
	 */
	public static function hex_colour( mixed $value ): string {
		$value = is_scalar( $value ) ? trim( (string) $value ) : '';

		return preg_match( '/^#[0-9a-f]{6}$/i', $value ) ? strtolower( $value ) : '';
	}

	/**
	 * An integer in a range, or null when nothing was chosen.
	 *
	 * For the settings that mean "no limit" when they are unset: a link that
	 * never expires, a download that is not capped. Empty string, null and
	 * zero all mean the same thing, because a select whose "unlimited" option
	 * has an empty value and a form that posts 0 are both saying it.
	 *
	 * Distinct from int(), which always returns a number. The difference is
	 * whether "not set" is a value the caller needs to keep.
	 *
	 * @since 1.1.0
	 *
	 * @param mixed $value Untrusted value.
	 * @param int   $min   Lower bound.
	 * @param int   $max   Upper bound.
	 *
	 * @return int|null The clamped integer, or null when unset.
	 */
	public static function int_or_null( mixed $value, int $min, int $max ): ?int {
		if ( ! is_numeric( $value ) || 0 === self::int( $value, PHP_INT_MIN, PHP_INT_MAX ) ) {
			return null;
		}

		return self::int( $value, $min, $max, $min );
	}

	/**
	 * One of a fixed set, or a default.
	 *
	 * The allow-list form of validation, which is the only one that works for
	 * values that reach SQL as identifiers — a sort column, a table alias.
	 * See the paginate library for what that looks like in practice.
	 *
	 * @since 1.0.0
	 *
	 * @param string             $value   Untrusted value.
	 * @param array<int, string> $allowed Permitted values.
	 * @param string|null        $default Returned when it is not one. Falls
	 *                                    back to the first permitted value,
	 *                                    or '' when none is permitted.
	 *
	 * @return string
	 */
	public static function one_of( string $value, array $allowed, ?string $default = null ): string {
		if ( in_array( $value, $allowed, true ) ) {
			return $value;
		}

		return $default ?? ( array() === $allowed ? '' : $allowed[ array_key_first( $allowed ) ] );
	}

	/**
	 * A list of prefixed ids, each checked as {@see prefixed_id()} checks one.
	 *
	 * For the form field or JSON array that names several objects — the
	 * prices in a cart, the products on a shelf. What does not match is
	 * dropped rather than failing the list, duplicates go, and the order
	 * the caller gave is kept, because it is usually a display order.
	 *
	 * Bounded on the way in: a list padded with ten thousand entries costs
	 * no more than one at the cap, so the cap is how many are read, not how
	 * many survive.
	 *
	 * @since 1.3.0
	 *
	 * @param mixed  $values A list, or one scalar. Anything else is empty.
	 * @param string $prefix Expected prefix, without the underscore.
	 * @param int    $max    Entries read at most. 0 for no limit.
	 *
	 * @return list<string>
	 */
	public static function prefixed_ids( mixed $values, string $prefix, int $max = 0 ): array {
		$values = is_array( $values ) ? array_values( $values ) : ( is_scalar( $values ) ? array( $values ) : array() );

		if ( $max > 0 ) {
			$values = array_slice( $values, 0, $max );
		}

		$ids = array();

		foreach ( $values as $value ) {
			$id = self::prefixed_id( is_scalar( $value ) ? (string) $value : '', $prefix );

			if ( '' !== $id ) {
				$ids[ $id ] = true;
			}
		}

		return array_map( strval( ... ), array_keys( $ids ) );
	}

	/**
	 * A switch, strictly.
	 *
	 * On is JSON true, 1, "1", "true", "on" or "yes"; off is their opposites,
	 * and the empty string.
	 * Anything else — "maybe", an array, a typo — is the default rather than
	 * whatever a truthiness cast makes of it: `(bool) "false"` is true, which
	 * is how a setting ends up doing the opposite of what somebody chose.
	 *
	 * @since 1.3.0
	 *
	 * @param mixed $value   Stored or submitted value.
	 * @param bool  $default Returned when the value is not a recognisable
	 *                       switch at all.
	 *
	 * @return bool
	 */
	public static function bool( mixed $value, bool $default = false ): bool {
		return filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE ) ?? $default;
	}

	/**
	 * A URL's origin — scheme, host, and a port if one was given — or ''.
	 *
	 * An origin and nothing more, because it is compared with where a
	 * browser says a request came from, and a path would be one more thing
	 * to get wrong. https only by default: an allow-listed http origin is a
	 * page anybody on the network in between can rewrite.
	 *
	 * Refused: anything carrying credentials (`https://user@host` reads as
	 * one host to a person and another to a parser), a host outside plain
	 * letters, digits, dots and hyphens, and any other scheme.
	 *
	 * @since 1.3.0
	 *
	 * @param mixed $value      A URL or an origin.
	 * @param bool  $https_only Refuse http:// as well. Default true.
	 *
	 * @return string Lower-cased `https://host[:port]`, or ''.
	 */
	public static function origin( mixed $value, bool $https_only = true ): string {
		$parts = parse_url( is_scalar( $value ) ? trim( (string) $value ) : '' );

		if ( ! is_array( $parts ) || isset( $parts['user'] ) || ! isset( $parts['host'] ) || '' === $parts['host'] ) {
			return '';
		}

		$scheme = strtolower( $parts['scheme'] ?? '' );

		if ( 'https' !== $scheme && ( $https_only || 'http' !== $scheme ) ) {
			return '';
		}

		$host = strtolower( $parts['host'] );

		return 1 === preg_match( '/^[a-z0-9.-]+$/D', $host )
			? $scheme . '://' . $host . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' )
			: '';
	}

	/**
	 * A list typed into one field, or sent as an array.
	 *
	 * A Dashboard metadata value or a textarea of origins is written with
	 * commas, spaces, new lines or all three; this reads them all the same
	 * way. Each entry is trimmed, empties and duplicates go, the order is
	 * kept. It does not judge the entries — pass each through the validator
	 * for what it should be.
	 *
	 * @since 1.3.0
	 *
	 * @param mixed $value A string, or an array of scalars. Anything else is
	 *                     empty.
	 * @param int   $max   Entries read at most, before duplicates are
	 *                     dropped. 0 for no limit.
	 *
	 * @return list<string>
	 */
	public static function list( mixed $value, int $max = 0 ): array {
		$parts = is_array( $value )
			? array_values( $value )
			: ( preg_split( '/[\s,]+/', is_scalar( $value ) ? (string) $value : '', -1, PREG_SPLIT_NO_EMPTY ) ?: array() );

		if ( $max > 0 ) {
			$parts = array_slice( $parts, 0, $max );
		}

		$list = array();

		foreach ( $parts as $part ) {
			$part = is_scalar( $part ) ? trim( (string) $part ) : '';

			if ( '' !== $part ) {
				$list[ $part ] = true;
			}
		}

		return array_map( strval( ... ), array_keys( $list ) );
	}

	/**
	 * One entry per line, from a textarea.
	 *
	 * For entries that can hold spaces or commas themselves — file paths,
	 * addresses, titles — where list() would split them apart. Lines are
	 * split on any line ending, each is trimmed, and blank ones go.
	 * Duplicates and order are kept: a position can mean something (a
	 * download link that points at "the second file"), so removing one is
	 * the caller's decision.
	 *
	 * @since 1.7.0
	 *
	 * @param mixed $value A string; anything else is empty.
	 * @param int   $max   Entries kept at most, 0 for no limit.
	 *
	 * @return list<string>
	 */
	public static function lines( mixed $value, int $max = 0 ): array {
		if ( ! is_string( $value ) ) {
			return array();
		}

		$lines = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $value ) ?: array() as $line ) {
			$line = trim( $line );

			if ( '' === $line ) {
				continue;
			}

			$lines[] = $line;

			if ( $max > 0 && count( $lines ) >= $max ) {
				break;
			}
		}

		return $lines;
	}

	/**
	 * A credential or name, shortened to what recognises it: `med…ia`.
	 *
	 * Enough of each end to tell two apart in a list, never enough to use.
	 * Four of each end from sixteen characters up — an access key — three
	 * and two from ten, and only the first character of anything shorter,
	 * where showing both ends would show half of it or more. Counted in
	 * characters, so a name is never cut through the middle of one.
	 *
	 * @since 1.3.0
	 *
	 * @param string $value The value to mask.
	 *
	 * @return string
	 */
	public static function mask( #[\SensitiveParameter] string $value ): string {
		$length = mb_strlen( $value );

		if ( $length < 10 ) {
			return mb_substr( $value, 0, 1 ) . '…';
		}

		return mb_substr( $value, 0, $length >= 16 ? 4 : 3 ) . '…' . mb_substr( $value, $length >= 16 ? -4 : -2 );
	}

	/**
	 * A list of numbers, each clamped to a range, or null when it is not one.
	 *
	 * For data a browser computed and sent back — a waveform's peaks, a
	 * chart's points. All or nothing: one entry that is not a number means
	 * the list was not what the page drew, and storing the rest would store
	 * something else. Numeric strings are refused too, because JSON numbers
	 * are what a script sends.
	 *
	 * @since 1.3.0
	 *
	 * @param mixed    $value     A list of ints and floats.
	 * @param float    $min       Lower bound for each.
	 * @param float    $max       Upper bound for each.
	 * @param int      $max_count Most entries allowed; more is not a list
	 *                            of this kind. 0 for no limit.
	 * @param int|null $decimals  Round each to this many places, or null to
	 *                            leave them.
	 *
	 * @return list<float>|null Null for an empty list too.
	 */
	public static function number_list( mixed $value, float $min, float $max, int $max_count = 0, ?int $decimals = null ): ?array {
		if ( ! is_array( $value ) || ! array_is_list( $value ) || array() === $value || ( $max_count > 0 && count( $value ) > $max_count ) ) {
			return null;
		}

		$numbers = array();

		foreach ( $value as $number ) {
			if ( ! is_int( $number ) && ! is_float( $number ) ) {
				return null;
			}

			if ( is_float( $number ) && is_nan( $number ) ) {
				return null;
			}

			$clamped   = max( $min, min( $max, (float) $number ) );
			$numbers[] = null === $decimals ? $clamped : round( $clamped, $decimals );
		}

		return $numbers;
	}

	/**
	 * Text with control and invisible characters removed.
	 *
	 * @since 1.4.0
	 *
	 * @param string $value Untrusted text.
	 *
	 * @return string '' when the text is not valid UTF-8.
	 */
	private static function strip( string $value ): string {
		$value = preg_replace( self::CONTROL, '', $value ) ?? '';

		return preg_replace( self::INVISIBLE, '', $value ) ?? '';
	}
}
