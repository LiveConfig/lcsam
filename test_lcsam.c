/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#include <sysexits.h>
#include <check.h>

#include "lcsam.h"
#include "args.h"
#include "lookup.h"

/* -------------------------------------------------------------------------
 * Set up environment for tests
 * ---------------------------------------------------------------------- */
static void test_lcsam_setup(void) {
	/* enable debug output */
	args_debug = 1;
	args_usermap = "test.map.db";
}

/* -------------------------------------------------------------------------
 * test lookup
 * ---------------------------------------------------------------------- */
START_TEST (test_lookup)
{
	int ret;
	struct lookup_result lr;

	ret = lookup_prefs(NULL, "test@example.org", &lr);
	ck_assert(ret == 0);
	ck_assert(lr.warn_score == 3.0);
	ck_assert(lr.reject_score == 5.5);
	ck_assert(lr.action == 1);
	ck_assert_msg(strcmp(lr.userid, "123/45") == 0, "userid: '%s' != '123/45'", lr.userid);
	ck_assert_msg(strcmp(lr.subjectprefix, "*** Spam-Verdacht ***") == 0, "subjectprefix: '%s' != '*** Spam-Verdacht ***'", lr.subjectprefix);

}
END_TEST

/* -------------------------------------------------------------------------
 * Test suite
 * ---------------------------------------------------------------------- */
static Suite *test_suite(void) {

	Suite *s = suite_create("lcsam");

	/* lookup test cases */
	TCase *tc_lookup = tcase_create("lookup");
	tcase_add_checked_fixture(tc_lookup, test_lcsam_setup, NULL);
	tcase_add_test(tc_lookup, test_lookup);
	suite_add_tcase(s, tc_lookup);

	return(s);
}

/* -------------------------------------------------------------------------
 * main() function
 * ---------------------------------------------------------------------- */
int main (int argc, char **argv) {
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return(number_failed == 0) ? EX_OK : EX_SOFTWARE;
}
