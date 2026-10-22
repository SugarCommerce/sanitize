<?php
/**
 * Input tests.
 *
 * @package SugarCommerce\Sanitize\Tests
 */

declare( strict_types=1 );

namespace SugarCommerce\Sanitize\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SugarCommerce\Sanitize\Input;

/**
 * Class InputTest
 */
final class InputTest extends TestCase {

	public function test_multiline_keeps_line_breaks(): void {
		$this->assertSame( "one\ntwo", Input::multiline( "one\ntwo" ) );
	}

	public function test_multiline_normalises_carriage_returns(): void {
		// The same note typed on Windows and on a Mac has to store the same,
		// or the length check fires for one of them and not the other.
		$this->assertSame( "one\ntwo", Input::multiline( "one\r\ntwo" ) );
		$this->assertSame( "one\ntwo", Input::multiline( "one\rtwo" ) );
	}

	public function test_multiline_collapses_horizontal_whitespace_only(): void {
		$this->assertSame( "a b\nc d", Input::multiline( "a   b\nc\t\td" ) );
	}

	public function test_multiline_collapses_runs_of_blank_lines(): void {
		$this->assertSame( "a\n\nb", Input::multiline( "a\n\n\n\n\nb" ) );
	}

	public function test_multiline_drops_trailing_spaces_before_a_break(): void {
		$this->assertSame( "a\nb", Input::multiline( "a   \nb" ) );
	}

	public function test_multiline_trims_the_whole_value(): void {
		$this->assertSame( 'a', Input::multiline( "\n\n  a  \n\n" ) );
	}

	public function test_multiline_strips_control_characters(): void {
		$this->assertSame( "ab\ncd", Input::multiline( "a\x00\x07b\ncd" ) );
	}

	public function test_multiline_strips_bidirectional_overrides(): void {
		$this->assertSame( 'exe.txt', Input::multiline( "\u{202E}exe.txt" ) );
	}

	public function test_multiline_limits_lines(): void {
		$this->assertSame( "a\nb", Input::multiline( "a\nb\nc\nd", 0, 2 ) );
		$this->assertSame( "a\nb\nc\nd", Input::multiline( "a\nb\nc\nd", 0, 0 ) );
	}

	public function test_multiline_truncates_by_characters(): void {
		$this->assertSame( 'ééé', Input::multiline( 'ééééé', 3 ) );
	}

	public function test_multiline_truncation_leaves_no_trailing_space(): void {
		$this->assertSame( 'ab', Input::multiline( 'ab cd', 3 ) );
	}

	public function test_multiline_refuses_anything_that_is_not_scalar(): void {
		$this->assertSame( '', Input::multiline( array( 'a' ) ) );
		$this->assertSame( '', Input::multiline( null ) );
	}

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

	/**
	 * FreshlyVault's admin lists: `•`, at least two of them, split at the
	 * last `@`, and anything that is not an address shown as stored.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function bulleted(): array {
		return array(
			'george'          => array( 'george@gmail.com', "ge\u{2022}\u{2022}\u{2022}\u{2022}@gmail.com" ),
			'one character'   => array( 'a@example.com', "a\u{2022}\u{2022}@example.com" ),
			'long'            => array( 'david.sherlock@x.co.uk', 'da' . str_repeat( "\u{2022}", 12 ) . '@x.co.uk' ),
			'two characters'  => array( 'ab@x', "ab\u{2022}\u{2022}@x" ),
			'last @'          => array( 'a@b@c.com', "a@\u{2022}\u{2022}@c.com" ),
			'no @'            => array( 'nope', 'nope' ),
			'nothing before'  => array( '@x.com', '@x.com' ),
			'empty'           => array( '', '' ),
		);
	}

	#[DataProvider( 'bulleted' )]
	public function test_mask_email_takes_a_mask_a_minimum_and_where_to_split( string $email, string $expected ): void {
		$this->assertSame( $expected, Input::mask_email( $email, "\u{2022}", 2, last_at: true, keep_invalid: true ) );
	}

	public function test_mask_email_defaults_are_unchanged(): void {
		$this->assertSame( 'a*@b@c.com', Input::mask_email( 'a@b@c.com' ) );
		$this->assertSame( '*@x.com', Input::mask_email( '@x.com' ) );
		$this->assertSame( 'ab*@x', Input::mask_email( 'ab@x' ) );
	}

	public function test_mask_email_masks_characters_not_bytes(): void {
		$this->assertSame( "jö\u{2022}\u{2022}@x.de", Input::mask_email( 'jörg@x.de', "\u{2022}", 2 ) );
		$this->assertSame( 'é*@x.de', Input::mask_email( 'é@x.de' ) );
	}

	public function test_mask_email_can_return_a_non_address_as_given(): void {
		$this->assertSame( 'nope', Input::mask_email( 'nope', keep_invalid: true ) );
		$this->assertSame( '', Input::mask_email( 'nope' ) );
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

	/* ── truncate ───────────────────────────────────────────────────── */

	public function test_truncate_trims_the_ends_only(): void {
		// Unlike clean_text, the inside is left exactly as written — this is
		// for HTML and templates, where collapsing whitespace changes them.
		$this->assertSame( "a\n\n  b", Input::truncate( "  a\n\n  b  " ) );
	}

	public function test_truncate_counts_characters_not_bytes(): void {
		$this->assertSame( 'ééé', Input::truncate( 'ééééé', 3 ) );
	}

	public function test_truncate_with_no_limit_keeps_everything(): void {
		$this->assertSame( str_repeat( 'a', 500 ), Input::truncate( str_repeat( 'a', 500 ) ) );
	}

	public function test_truncate_refuses_a_non_scalar(): void {
		$this->assertSame( '', Input::truncate( array( 'a' ) ) );
	}

	/* ── prefixed id lists ──────────────────────────────────────────── */

	public function test_prefixed_ids_keeps_valid_ids_in_order_once(): void {
		$this->assertSame(
			array( 'price_b', 'price_a' ),
			Input::prefixed_ids( array( 'price_b', 'prod_x', ' price_a ', 'price_b', '', array( 'x' ) ), 'price' )
		);
	}

	public function test_prefixed_ids_reads_no_more_than_the_cap(): void {
		// The cap is on what is read, so a list padded with junk in front
		// cannot push a real id past it into being counted.
		$this->assertSame( array( 'prod_a' ), Input::prefixed_ids( array( 'prod_a', 'nope', 'prod_b' ), 'prod', 2 ) );
	}

	public function test_prefixed_ids_takes_one_scalar_and_refuses_the_rest(): void {
		$this->assertSame( array( 'prod_a' ), Input::prefixed_ids( 'prod_a', 'prod' ) );
		$this->assertSame( array(), Input::prefixed_ids( null, 'prod' ) );
		$this->assertSame( array(), Input::prefixed_ids( new \stdClass(), 'prod' ) );
	}

	/* ── switches ───────────────────────────────────────────────────── */

	/**
	 * Values and what they mean, with a default of false.
	 *
	 * @return array<string, array{0: mixed, 1: bool}>
	 */
	public static function switches(): array {
		return array(
			'true'          => array( true, true ),
			'one'           => array( 1, true ),
			'string one'    => array( '1', true ),
			'string true'   => array( 'true', true ),
			'on'            => array( 'on', true ),
			'yes'           => array( 'yes', true ),
			'false'         => array( false, false ),
			'string false'  => array( 'false', false ),
			'zero'          => array( '0', false ),
			'off'           => array( 'off', false ),
			'nonsense'      => array( 'maybe', false ),
			'array'         => array( array( 1 ), false ),
			'null'          => array( null, false ),
		);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider( 'switches' )]
	public function test_bool_reads_switches_strictly( mixed $value, bool $expected ): void {
		$this->assertSame( $expected, Input::bool( $value ) );
	}

	public function test_bool_falls_back_to_the_default_only_for_nonsense(): void {
		$this->assertTrue( Input::bool( 'maybe', true ) );
		$this->assertFalse( Input::bool( 'false', true ) );
	}

	/* ── origins ────────────────────────────────────────────────────── */

	public function test_origin_keeps_scheme_host_and_port_only(): void {
		$this->assertSame( 'https://shop.example.com', Input::origin( ' https://Shop.Example.com/path?q=1 ' ) );
		$this->assertSame( 'https://example.com:8443', Input::origin( 'https://example.com:8443/x' ) );
	}

	public function test_origin_refuses_http_unless_asked(): void {
		$this->assertSame( '', Input::origin( 'http://example.com' ) );
		$this->assertSame( 'http://localhost:8080', Input::origin( 'http://localhost:8080/', false ) );
	}

	public function test_origin_refuses_credentials_odd_hosts_and_other_schemes(): void {
		$this->assertSame( '', Input::origin( 'https://user@example.com' ) );
		$this->assertSame( '', Input::origin( 'https://exa mple.com' ) );
		$this->assertSame( '', Input::origin( 'javascript:alert(1)' ) );
		$this->assertSame( '', Input::origin( 'example.com' ) );
		$this->assertSame( '', Input::origin( array( 'https://example.com' ) ) );
	}

	/* ── lists ──────────────────────────────────────────────────────── */

	public function test_list_splits_on_commas_spaces_and_lines(): void {
		$this->assertSame( array( 'a', 'b', 'c', 'd' ), Input::list( "a, b\nc ,,d  a" ) );
	}

	public function test_list_takes_an_array_and_drops_what_is_not_text(): void {
		$this->assertSame( array( 'a', 'b' ), Input::list( array( ' a ', '', array( 'x' ), 'b', 'a' ) ) );
	}

	public function test_list_reads_no_more_than_the_cap(): void {
		$this->assertSame( array( 'a', 'b' ), Input::list( 'a,b,c', 2 ) );
		$this->assertSame( array(), Input::list( null ) );
	}

	/* ── masks ──────────────────────────────────────────────────────── */

	public function test_mask_shows_both_ends_of_a_long_value(): void {
		$this->assertSame( 'AKIA…WXYZ', Input::mask( 'AKIA0123456789WXYZ' ) );
		$this->assertSame( 'med…ia', Input::mask( 'media-bucket-ia' ) );
	}

	public function test_mask_shows_one_character_of_a_short_value(): void {
		$this->assertSame( 'a…', Input::mask( 'abcdef' ) );
		$this->assertSame( '…', Input::mask( '' ) );
	}

	/* ── number lists ───────────────────────────────────────────────── */

	public function test_number_list_clamps_and_rounds(): void {
		$this->assertSame( array( 0.0, 0.33, 1.0 ), Input::number_list( array( -1, 0.3333, 7 ), 0.0, 1.0, 0, 2 ) );
	}

	public function test_number_list_is_all_or_nothing(): void {
		$this->assertNull( Input::number_list( array( 0.1, '0.2' ), 0.0, 1.0 ) );
		$this->assertNull( Input::number_list( array(), 0.0, 1.0 ) );
		$this->assertNull( Input::number_list( array( 'a' => 0.1 ), 0.0, 1.0 ) );
		$this->assertNull( Input::number_list( '0.1,0.2', 0.0, 1.0 ) );
	}

	public function test_number_list_refuses_more_than_the_cap(): void {
		$this->assertNull( Input::number_list( array( 0.1, 0.2, 0.3 ), 0.0, 1.0, 2 ) );
		$this->assertSame( array( 0.1, 0.2 ), Input::number_list( array( 0.1, 0.2 ), 0.0, 1.0, 2 ) );
	}

	/* ── found in review ─────────────────────────────────────────────── */

	/**
	 * The bidirectional isolates are what "Trojan Source" used, and the
	 * docblock always promised C1 as well as C0.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function invisible(): array {
		return array(
			'right-to-left isolate'    => array( "\u{2067}" ),
			'first-strong isolate'     => array( "\u{2068}" ),
			'pop directional isolate'  => array( "\u{2069}" ),
			'left-to-right isolate'    => array( "\u{2066}" ),
			'Arabic letter mark'       => array( "\u{061C}" ),
			'soft hyphen'              => array( "\u{00AD}" ),
			'Mongolian vowel separator' => array( "\u{180E}" ),
			'Hangul filler'            => array( "\u{3164}" ),
			'a tag character'          => array( "\u{E0041}" ),
			'C1 next line'             => array( "\u{0085}" ),
			'C1 control'               => array( "\u{009B}" ),
		);
	}

	#[DataProvider( 'invisible' )]
	public function test_clean_text_strips_every_invisible_character( string $character ): void {
		$this->assertSame( 'exe.txt', Input::clean_text( "exe{$character}.txt" ) );
		$this->assertSame( 'exe.txt', Input::multiline( "exe{$character}.txt" ) );
	}

	/**
	 * The first 254 characters of a longer string are a different address.
	 */
	public function test_an_address_too_long_is_refused_rather_than_cut(): void {
		$this->assertSame( '', Input::email( str_repeat( 'a', 60 ) . '@' . str_repeat( 'b', 63 ) . '.' . str_repeat( 'c', 63 ) . '.' . str_repeat( 'd', 63 ) . '.example.org' ) );
	}

	public function test_a_url_too_long_is_refused_rather_than_cut(): void {
		$this->assertSame( '', Input::url( 'https://example.com/' . str_repeat( 'a', 2100 ) ) );
	}

	/**
	 * A float past PHP_INT_MAX cast to 0 with a warning, which int_or_null()
	 * read as "nothing chosen" — no limit at all.
	 */
	public function test_a_number_too_big_for_an_int_clamps_to_the_maximum(): void {
		$this->assertSame( 10, Input::int( 1e30, 1, 10 ) );
		$this->assertSame( 10, Input::int( '1e30', 1, 10 ) );
		$this->assertSame( 1, Input::int( -1e30, 1, 10 ) );
		$this->assertSame( 100, Input::int_or_null( 1e30, 1, 100 ) );
		$this->assertSame( 3, Input::int( NAN, 1, 10, 3 ) );
	}

	public function test_one_of_with_nothing_permitted_is_empty(): void {
		$this->assertSame( '', Input::one_of( 'a', array() ) );
		$this->assertSame( 'b', Input::one_of( 'z', array( 2 => 'b' ) ) );
	}

	public function test_hex_of_a_length_below_one_is_empty(): void {
		$this->assertSame( '', Input::hex( '', 0 ) );
		$this->assertSame( '', Input::hex( 'ab', -1 ) );
	}

	/**
	 * Five of seven characters is most of a secret.
	 */
	public function test_mask_shows_one_character_below_ten(): void {
		$this->assertSame( 's…', Input::mask( 'secret1' ) );
		$this->assertSame( 'sec…90', Input::mask( 'secret7890' ) );
	}

	public function test_mask_never_cuts_a_character_in_half(): void {
		$masked = Input::mask( 'ééééééééééé' );

		$this->assertSame( 'ééé…éé', $masked );
		$this->assertTrue( mb_check_encoding( $masked, 'UTF-8' ) );
	}

	public function test_number_list_refuses_nan(): void {
		$this->assertNull( Input::number_list( array( 0.5, NAN ), 0, 1 ) );
	}
}
