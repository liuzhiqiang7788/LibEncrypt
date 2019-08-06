#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <windows.h>


namespace ibex {

	namespace encryption {

		typedef std::basic_string<TCHAR> tstring;
		typedef std::vector<unsigned char> encryptBufferData_t;

		class CIbexFileEncryption
		{
		public:
			CIbexFileEncryption(const tstring &key);
			~CIbexFileEncryption();
			unsigned long encrypt(const encryptBufferData_t &_buffer, const tstring &_destFilePath);
			unsigned long decrypt(const tstring &_srcFilePath, encryptBufferData_t &_buffer);
		private:
			tstring m_sKey;
		};

	} //namespace encryption

} //namespace ibex
