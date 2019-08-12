#include "stdafx.h"
#include "IbexFileEncryption.h"
#include "define.h"
#include <errno.h>
#include <stdlib.h>
#include <vector>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>

namespace ibex {

	namespace encryption {

		CIbexFileEncryption::CIbexFileEncryption(const tstring &key)
		{
			m_sKey = key.c_str();
		}

		CIbexFileEncryption::~CIbexFileEncryption()
		{

		}

		unsigned long CIbexFileEncryption::encrypt(const encryptBufferData_t &_buffer, const tstring &_destFilePath)
		{
			// need check _buffer whether is empty
			if (_buffer.empty())
			{
				std::cout << "buffer invalid" << std::endl;
				return IBEX_ENCRYPTION_BUFFER_EMPTY;
			}
			if (_destFilePath.empty())
			{
				std::cout << "dest file path invalid" << std::endl;
				return IBEX_ENCRYPTION_FILE_EMPTY;
			}
			if (m_sKey.size() != 32)
			{
				std::cout << "key value is null" << std::endl;
				return IBEX_ENCRYPTION_KEY_INVALID;
			}

			try
			{
				// allocate a memory prepare for encrypt need smart class pointer
				int buf_len = _buffer.size();
				int origin_len = 2 * buf_len;
				encryptBufferData_t encrypt_buffer(origin_len);
				EVP_CIPHER_CTX ctx;
				encryptBufferData_t iv(EVP_MAX_IV_LENGTH);
				int ret;
				int total_len = 0;
				int update_len = 0;
				int final_len = 0;

				//encrypt process
				EVP_CIPHER_CTX_init(&ctx);

				std::vector<char> CombineKey(m_sKey.size());
				WideCharToMultiByte(CP_ACP, 0, m_sKey.c_str(), wcslen(m_sKey.c_str()), &CombineKey[0], m_sKey.size(), NULL, NULL);

				ret = EVP_EncryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, (unsigned char*)&CombineKey[0], (unsigned char*)&iv[0]);
				if (ret != 1) {
					std::cout << "EVP_EncryptInit_ex failed" << std::endl;
					return IBEX_ENCRYPTION_INIT_FAILED;
				}

				ret = EVP_EncryptUpdate(&ctx, (unsigned char*)&encrypt_buffer[0], &update_len, (unsigned char*)&_buffer[0], buf_len);
				if (ret != 1) {
					std::cout << "EVP_EncryptUpdate failed" << std::endl;
					return IBEX_ENCRYPTION_UPDATE_FAILED;
				}
				if (update_len >= origin_len)
				{
					int n = update_len / origin_len;
					encrypt_buffer.resize((n + 1) * origin_len);
				}

				ret = EVP_EncryptFinal_ex(&ctx, (unsigned char*)&encrypt_buffer[update_len], &final_len);
				if (ret != 1) {
					std::cout << "EVP_EncryptFinal_ex failed" << std::endl;
					return IBEX_ENCRYPTION_FINAL_FAILED;
				}

				total_len = update_len + final_len;

				// write file
				std::ofstream out;
				out.open(_destFilePath, std::ios::out | std::ios::binary);
				if (!out.is_open())
				{
					std::cout << "open dest file failed!" << std::endl;
					return IBEX_ENCRYPTION_FILE_OPEN_FAILED;
				}

				out.write((const char*)&encrypt_buffer[0], total_len);
				out.close();
			}
			catch (const std::exception& e)
			{
				std::cerr << "encrypt exception caused by: " << e.what() << std::endl;
				return IBEX_ENCRYPTION_EXCEPTION;
			}

			return IBEX_ENCRYPTION_SUCCESS;
		}

		unsigned long CIbexFileEncryption::decrypt(const tstring &_srcFilePath, encryptBufferData_t &_buffer)
		{
			// check input parameter valid
			if (_srcFilePath.empty())
			{
				return IBEX_ENCRYPTION_FILE_EMPTY;
			}
			if (m_sKey.size() != 32)
			{
				return IBEX_ENCRYPTION_KEY_INVALID;
			}
			try
			{
				std::ifstream in;
				in.open(_srcFilePath, std::ios::in | std::ios::binary);
				if (!in.is_open())
				{
					std::cout << "open src file failed!" << std::endl;
					return IBEX_ENCRYPTION_FILE_OPEN_FAILED;
				}
				std::stringstream buffer;
				buffer << in.rdbuf();
				in.close();

				int encrypt_len = buffer.str().size();
				encryptBufferData_t decrypt_buff(encrypt_len);

				// decrypt process and copy decrypt data to buffer
				encryptBufferData_t iv(EVP_MAX_IV_LENGTH);
				EVP_CIPHER_CTX ctx;
				int ret;
				int total_len = 0;
				int update_len = 0;
				int final_len = 0;

				EVP_CIPHER_CTX_init(&ctx);

				std::vector<char> CombineKey(m_sKey.size());
				WideCharToMultiByte(CP_ACP, 0, m_sKey.c_str(), wcslen(m_sKey.c_str()), &CombineKey[0], m_sKey.size(), NULL, NULL);

				ret = EVP_DecryptInit_ex(&ctx, EVP_aes_256_ecb(), NULL, (unsigned char*)&CombineKey[0], (unsigned char*)&iv[0]);
				if (ret != 1) {
					std::cout << "EVP_DecryptInit_ex failed" << std::endl;
					return IBEX_ENCRYPTION_INIT_FAILED;
				}

				ret = EVP_DecryptUpdate(&ctx, (unsigned char*)&decrypt_buff[0], &update_len, (unsigned char*)buffer.str().c_str(), encrypt_len);
				if (ret != 1) {
					std::cout << "EVP_DecryptUpdate failed" << std::endl;
					return IBEX_ENCRYPTION_UPDATE_FAILED;
				}
				if (update_len >= encrypt_len)
				{
					int n = update_len / encrypt_len;
					decrypt_buff.resize((n + 1) * encrypt_len);
				}

				ret = EVP_DecryptFinal_ex(&ctx, (unsigned char*)&decrypt_buff[update_len], &final_len);
				if (ret != 1) {
					std::cout << "EVP_DecryptFinal_ex failed" << std::endl;
					return IBEX_ENCRYPTION_FINAL_FAILED;
				}
				total_len = update_len + final_len;

				_buffer.clear();
				_buffer.assign(decrypt_buff.begin(), decrypt_buff.begin() + total_len);
			}
			catch (const std::exception& e)
			{
				std::cerr << "exception caused by: " << e.what() << std::endl;
				return IBEX_ENCRYPTION_EXCEPTION;
			}

			return IBEX_ENCRYPTION_SUCCESS;
		}
	} //namespace encryption

} //namespace ibex