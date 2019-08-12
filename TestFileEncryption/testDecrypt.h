#pragma once

#include <boost/test/included/unit_test.hpp>
#include "../IbexFileEncryptionLib/IbexFileEncryption.h"
using namespace std;

BOOST_AUTO_TEST_SUITE(Decrypt_tests)

BOOST_AUTO_TEST_CASE(Decrypt_testFile)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("12345"));
	ibex::encryption::encryptBufferData_t buff;


	unsigned long ret = encrypt.decrypt(L"", buff);

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_FILE_EMPTY, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_FILE_EMPTY, "decrypt dest file is empty");
}

BOOST_AUTO_TEST_CASE(Decrypt_testKeyValid)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("12345"));
	ibex::encryption::encryptBufferData_t buff;

	unsigned long ret = encrypt.decrypt(_T("C:\\TEST\\test.txt"),buff);

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_KEY_INVALID, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_KEY_INVALID, "encrypt key is invalid");
}

BOOST_AUTO_TEST_CASE(Decrypt_testNormal)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("1234567890123456"));
	ibex::encryption::encryptBufferData_t de_buff;
	ibex::encryption::encryptBufferData_t en_buf;
	en_buf.clear();
	en_buf.assign(51263, 'a');

	unsigned long ret = encrypt.encrypt(en_buf, _T("C:\\TEST\\test3.txt"));

	ret = encrypt.decrypt(_T("C:\\TEST\\test3.txt"), de_buff);

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_SUCCESS, ret);
	BOOST_CHECK_EQUAL(TRUE, en_buf == de_buff);
}

BOOST_AUTO_TEST_CASE(Decrypt_testWrongKey)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("1234567890123456"));
	ibex::encryption::encryptBufferData_t de_buff;
	ibex::encryption::encryptBufferData_t en_buf;
	en_buf.clear();
	en_buf.assign(51263, 'a');

	unsigned long ret = encrypt.encrypt(en_buf, _T("C:\\TEST\\test.txt"));

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_SUCCESS, ret);
	BOOST_CHECK_EQUAL(TRUE, en_buf == de_buff);
}

BOOST_AUTO_TEST_SUITE_END()