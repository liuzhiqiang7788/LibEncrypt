#pragma once
#include <boost/test/included/unit_test.hpp>
#include "../IbexFileEncryptionLib/define.h"
#include "../IbexFileEncryptionLib/IbexFileEncryption.h"
#include <tchar.h>
using namespace std;

BOOST_AUTO_TEST_SUITE(Encrypt_tests)

BOOST_AUTO_TEST_CASE(Encrypt_testFile)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("12345"));
	ibex::encryption::encryptBufferData_t buff;
	buff.assign(10, 'a');
	
	unsigned long ret = encrypt.encrypt(buff,_T(""));

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_FILE_EMPTY, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_FILE_EMPTY, "encrypt dest file is empty");
}

BOOST_AUTO_TEST_CASE(Encrypt_testKey)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T(""));
	ibex::encryption::encryptBufferData_t buff;
	buff.assign(10, 'a');

	unsigned long ret = encrypt.encrypt(buff, _T("C:\\TEST\\test.txt"));

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_KEY_INVALID, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_KEY_INVALID, "encrypt key is invalid");
}

BOOST_AUTO_TEST_CASE(Encrypt_testBuffer)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("12345"));
	ibex::encryption::encryptBufferData_t buff;

	unsigned long ret = encrypt.encrypt(buff, _T("C:\\TEST\\test.txt"));

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_BUFFER_EMPTY, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_BUFFER_EMPTY, "encrypt buffer is empty");
}

BOOST_AUTO_TEST_CASE(Encrypt_testNormal)
{
	ibex::encryption::CIbexFileEncryption encrypt(_T("123456789012345678901234567890aa"));
	ibex::encryption::encryptBufferData_t buff;

	buff.assign(33, 'a');
	unsigned long ret = encrypt.encrypt(buff, _T("C:\\TEST\\test.txt"));

	BOOST_CHECK_EQUAL(IBEX_ENCRYPTION_SUCCESS, ret);
	BOOST_CHECK_MESSAGE(ret == IBEX_ENCRYPTION_SUCCESS, "encrypt buffer success");

}

BOOST_AUTO_TEST_SUITE_END()
