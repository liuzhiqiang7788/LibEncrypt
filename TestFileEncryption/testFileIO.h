#pragma once
#include <boost/test/included/unit_test.hpp>
#include "../IbexFileEncryptionLib/define.h"
#include "../IbexFileEncryptionLib/IbexFileEncryption.h"


BOOST_AUTO_TEST_SUITE(FileIO_tests)

BOOST_AUTO_TEST_CASE(FileIO_testcase1)
{
	const ibex::encryption::tstring sTemplate(("Hello /\\World/\\"));
	BOOST_TEST(true);
}

BOOST_AUTO_TEST_CASE(FileIO_testcase2)
{
	BOOST_TEST(false);
	BOOST_CHECK_EQUAL(1,2);
}

BOOST_AUTO_TEST_SUITE_END()