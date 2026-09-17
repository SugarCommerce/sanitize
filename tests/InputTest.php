<?php
/**
 * Input tests.
 *
 * @package SugarCommerce\Sanitize\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\Sanitize\Tests;

use PHPUnit\Framework\TestCase;
use SugarCommerce\Sanitize\Input;

/**
 * Class InputTest
 */
final class InputTest extends TestCase {

	public function test_clean_text_collapses_whitespace(): void {
		$this->assertSame( 'a b', Input::clean_text( "  a \n\t b  " ) );
	}

	public function test_clean_text_strips_control_characters(): void {
		$this->assertSame( 'ab', Input::clean_text( "a\x00\x07b" ) );
	}

	public function test_clean_text_strips_bidirectional_overrides(): void {
		// U+202E is what turns "exe.txt" into something that renders as
		// "txt.exe" in a file listing.
		$this->assertSame( 'exe.txt', Input::clean_text( "\u{202E}exe.txt" ) );
	}

	public function test_clean_text_strips_zero_width_characters(): void {
		$this->assertSame( 'ab', Input::clean_text( "a\u{200B}b" ) );
		$this->assertSame( 'ab', Input::clean_text( "\u{FEFF}ab" ) );
	}

	public function test_clean_text_truncates(): void {
		$this->assertSame( 'abcde', Input::clean_text( 'abcdefghij', 5 ) );
		$this->assertSame( 'abcdefghij', Input::clean_text( 'abcdefghij', 0 ) );
	}

	public function test_clean_text_truncates_by_characters_not_bytes(): void {
		$this->assertSame( 'ééé', Input::clean_text( 'ééééé', 3 ) );
	}

	public function test_email_lower_cases_only_the_domain(): void {
		$this->assertSame( 'Jordan@example.com', Input::email( 'Jordan@EXAMPLE.COM' ) );
	}

	public function test_email_rejects_rubbish(): void {
		$this->assertSame( '', Input::email( 'not-an-address' ) );
		$this->assertSame( '', Input::email( 'two@at@signs.com' ) );
		$this->assertSame( '', Input::email( '' ) );
	}

	public function test_email_trims_before_validating(): void {
		$this->assertSame( 'a@b.com', Input::email( '  a@b.com  ' ) );
	}

	public function test_mask_email_keeps_two_characters_and_the_domain(): void {
		$this->assertSame( 'jo****@example.com', Input::mask_email( 'jordan@example.com' ) );
	}

	public function test_mask_email_handles_a_one_character_local_part(): void {
		$this->assertSame( 'a*@example.com', Input::mask_email( 'a@example.com' ) );
	}

	public function test_mask_email_rejects_a_non_address(): void {
		$this->assertSame( '', Input::mask_email( 'nope' ) );
	}

	public function test_url_accepts_http_and_https(): void {
		$this->assertSame( 'https://example.com/a', Input::url( 'https://example.com/a' ) );
		$this->assertSame( 'http://example.com', Input::url( 'http://example.com' ) );
	}

	public function test_url_rejects_script_bearing_schemes(): void {
		$this->assertSame( '', Input::url( 'javascript:alert(1)' ) );
		$this->assertSame( '', Input::url( 'data:text/html,<script>' ) );
		$this->assertSame( '', Input::url( 'file:///etc/passwd' ) );
	}

	public function test_prefixed_id_requires_the_prefix(): void {
		$this->assertSame( 'acct_123abc', Input::prefixed_id( 'acct_123abc', 'acct' ) );
		$this->assertSame( '', Input::prefixed_id( 'cus_123abc', 'acct' ) );
		$this->assertSame( '', Input::prefixed_id( 'acct', 'acct' ) );
	}

	public function test_prefixed_id_rejects_punctuation(): void {
		$this->assertSame( '', Input::prefixed_id( 'acct_1/../2', 'acct' ) );
		$this->assertSame( '', Input::prefixed_id( "acct_1'", 'acct' ) );
	}

	public function test_hex_requires_an_exact_length(): void {
		$this->assertSame( 'abc123', Input::hex( 'ABC123', 6 ) );
		$this->assertSame( '', Input::hex( 'abc12', 6 ) );
		$this->assertSame( '', Input::hex( 'abc123g', 7 ) );
	}

	public function test_int_clamps_rather_than_rejecting(): void {
		$this->assertSame( 10, Input::int( 999, 1, 10 ) );
		$this->assertSame( 1, Input::int( -5, 1, 10 ) );
		$this->assertSame( 5, Input::int( '5', 1, 10 ) );
	}

	public function test_int_falls_back_when_not_numeric(): void {
		$this->assertSame( 3, Input::int( 'abc', 1, 10, 3 ) );
		$this->assertSame( 3, Input::int( null, 1, 10, 3 ) );
	}

	public function test_one_of_falls_back_to_the_first_permitted_value(): void {
		$this->assertSame( 'a', Input::one_of( 'z', array( 'a', 'b' ) ) );
		$this->assertSame( 'b', Input::one_of( 'b', array( 'a', 'b' ) ) );
	}

	public function test_one_of_takes_an_explicit_default(): void {
		$this->assertSame( '', Input::one_of( 'z', array( '', 'a', 'b' ), '' ) );
	}

	/* ── colours ────────────────────────────────────────────────────── */

	public function test_a_hex_colour_is_lower_cased(): void {
		$this->assertSame( '#6d28d9', Input::hex_colour( '#6D28D9' ) );
		$this->assertSame( '#ffffff', Input::hex_colour( '  #FFFFFF  ' ) );
	}

	/**
	 * The dangerous input is not `<script>`, which every escaper catches. It
	 * is `red;background:url(...)`, which survives escaping and is still CSS.
	 */
	public function test_anything_that_is_not_six_hex_digits_is_refused(): void {
		$this->assertSame( '', Input::hex_colour( 'red' ) );
		$this->assertSame( '', Input::hex_colour( 'red;background:url(//evil)' ) );
		$this->assertSame( '', Input::hex_colour( '#fff' ) );
		$this->assertSame( '', Input::hex_colour( '#6d28d9;x' ) );
		$this->assertSame( '', Input::hex_colour( '' ) );
	}

	public function test_a_non_scalar_colour_is_refused(): void {
		$this->assertSame( '', Input::hex_colour( array( '#6d28d9' ) ) );
		$this->assertSame( '', Input::hex_colour( null ) );
	}

	/* ── optional integers ──────────────────────────────────────────── */

	/**
	 * A select whose "unlimited" option has an empty value and a form that
	 * posts 0 are both saying the same thing.
	 */
	public function test_unset_means_null_however_it_arrives(): void {
		foreach ( array( null, '', 0, '0' ) as $unset ) {
			$this->assertNull( Input::int_or_null( $unset, 1, 100 ) );
		}
	}

	public function test_a_chosen_value_is_clamped(): void {
		$this->assertSame( 30, Input::int_or_null( 30, 1, 100 ) );
		$this->assertSame( 100, Input::int_or_null( 999, 1, 100 ) );
		$this->assertSame( 1, Input::int_or_null( -5, 1, 100 ) );
	}

	public function test_a_numeric_string_is_accepted(): void {
		$this->assertSame( 30, Input::int_or_null( '30', 1, 100 ) );
	}

	public function test_nonsense_is_null_rather_than_the_minimum(): void {
		// int() would return a default here; the caller of int_or_null needs
		// to know nothing was chosen.
		$this->assertNull( Input::int_or_null( 'abc', 1, 100 ) );
		$this->assertNull( Input::int_or_null( array( 5 ), 1, 100 ) );
	}

	/* ── non-scalar input generally ─────────────────────────────────── */

	/**
	 * A caller casting (string) on an array gets "Array" and a warning, and
	 * "Array" is a value that reaches a database.
	 */
	public function test_arrays_do_not_become_the_word_array(): void {
		$this->assertSame( '', Input::clean_text( array( 'a', 'b' ) ) );
		$this->assertSame( '', Input::email( array( 'a@b.com' ) ) );
		$this->assertSame( '', Input::url( array( 'https://a.test' ) ) );
	}

	public function test_null_is_empty_rather_than_an_error(): void {
		$this->assertSame( '', Input::clean_text( null ) );
		$this->assertSame( '', Input::email( null ) );
		$this->assertSame( '', Input::url( null ) );
	}

	public function test_numbers_still_clean_to_text(): void {
		$this->assertSame( '42', Input::clean_text( 42 ) );
	}
}
