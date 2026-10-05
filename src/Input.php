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
	 * Strip control characters and collapse whitespace.
	 *
	 * Removes the C0 and C1 ranges except tab, newline and carriage return,
	 * plus the Unicode characters used for display spoofing: zero-width
	 * joiners, bidirectional overrides and the byte-order mark. A filename
	 * containing U+202E renders right-to-left and can make `exe.txt` look
	 * like `txt.exe`, which is a real upload attack and not a theoretical one.
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

		$value = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', (string) $value ) ?? '';
		$value = preg_replace( '/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/u', '', $value ) ?? '';
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

		$value = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', (string) $value ) ?? '';
		$value = preg_replace( '/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/u', '', $value ) ?? '';

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
	 * @since 1.0.0
	 *
	 * @param mixed $value Untrusted address.
	 *
	 * @return string The address, or '' when it is not one.
	 */
	public static function email( mixed $value ): string {
		$value = self::clean_text( $value, 254 );

		if ( ! str_contains( $value, '@' ) ) {
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
	 * @since 1.0.0
	 *
	 * @param string $value An address.
	 *
	 * @return string The masked form, or '' when the input was not an address.
	 */
	public static function mask_email( string $value ): string {
		if ( ! str_contains( $value, '@' ) ) {
			return '';
		}

		[ $local, $domain ] = explode( '@', $value, 2 );
		$keep               = mb_substr( $local, 0, min( 2, mb_strlen( $local ) ) );

		return $keep . str_repeat( '*', max( 1, mb_strlen( $local ) - mb_strlen( $keep ) ) ) . '@' . $domain;
	}

	/**
	 * An http(s) URL, or ''.
	 *
	 * Other schemes are rejected outright. `javascript:` and `data:` are the
	 * ones that matter — both become script execution the moment the value
	 * reaches an href, and `filter_var` alone accepts them happily.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value Untrusted URL.
	 *
	 * @return string The URL, or '' when it is not a usable one.
	 */
	public static function url( mixed $value ): string {
		$value  = self::clean_text( $value, 2048 );
		$scheme = strtolower( (string) parse_url( $value, PHP_URL_SCHEME ) );

		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		return false === filter_var( $value, FILTER_VALIDATE_URL ) ? '' : $value;
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

		return preg_match( '/^' . preg_quote( $prefix, '/' ) . '_[A-Za-z0-9_]+$/', $value ) ? $value : '';
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
	 * @return string The lower-cased hex, or ''.
	 */
	public static function hex( string $value, int $length ): string {
		$value = trim( $value );

		return preg_match( '/^[a-f0-9]{' . $length . '}$/i', $value ) ? strtolower( $value ) : '';
	}

	/**
	 * An integer clamped to a range.
	 *
	 * Clamped rather than rejected: a page number of 10,000,000 is somebody
	 * fuzzing, and answering with the last page is a better response than an
	 * error page that tells them the query ran.
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

		return max( $min, min( $max, (int) $value ) );
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
		if ( null === $value || '' === $value || ! is_numeric( $value ) || 0 === (int) $value ) {
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
	 *                                    back to the first permitted value.
	 *
	 * @return string
	 */
	public static function one_of( string $value, array $allowed, ?string $default = null ): string {
		return in_array( $value, $allowed, true ) ? $value : ( $default ?? $allowed[0] );
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
	 * @return string[]
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

		return array_map( 'strval', array_keys( $ids ) );
	}

	/**
	 * A switch, strictly.
	 *
	 * On is JSON true, 1, "1", "true", "on" or "yes"; off is their opposites.
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

		if ( ! is_array( $parts ) || isset( $parts['user'] ) || '' === (string) ( $parts['host'] ?? '' ) ) {
			return '';
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );

		if ( 'https' !== $scheme && ( $https_only || 'http' !== $scheme ) ) {
			return '';
		}

		$host = strtolower( (string) $parts['host'] );

		return 1 === preg_match( '/^[a-z0-9.-]+$/', $host )
			? $scheme . '://' . $host . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' )
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
	 * @return string[]
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

		return array_map( 'strval', array_keys( $list ) );
	}

	/**
	 * A credential or name, shortened to what recognises it: `med…ia`.
	 *
	 * Enough of each end to tell two apart in a list, never enough to use.
	 * Four of each end from sixteen characters up — an access key — three
	 * and two below that, and only the first character of something six or
	 * shorter, where showing both ends would show most of it.
	 *
	 * @since 1.3.0
	 *
	 * @param string $value The value to mask.
	 *
	 * @return string
	 */
	public static function mask( #[\SensitiveParameter] string $value ): string {
		$length = strlen( $value );

		if ( $length <= 6 ) {
			return substr( $value, 0, 1 ) . '…';
		}

		return substr( $value, 0, $length >= 16 ? 4 : 3 ) . '…' . substr( $value, $length >= 16 ? -4 : -2 );
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
	 * @return array<int, float>|null Null for an empty list too.
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

			$clamped   = max( $min, min( $max, (float) $number ) );
			$numbers[] = null === $decimals ? $clamped : round( $clamped, $decimals );
		}

		return $numbers;
	}
}
