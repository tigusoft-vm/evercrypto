#ifndef CRYPTO_RANDOM_GENERATOR_HPP
#define CRYPTO_RANDOM_GENERATOR_HPP

#include <string>
#include <fstream>
#include <stdexcept>

using std::string;
using std::ifstream;
using std::ios_base;

#if defined _WIN32 || defined __CYGWIN__
	#include <windows.h>
	#include <wincrypt.h>
#else
	#define RANDOM_DEVICE "/dev/urandom"
#endif


template <typename type>
class c_random_generator {
private:
	static std::ifstream m_reader;

public:
	c_random_generator () = default;

	~c_random_generator () = default;
#if !defined(__CYGWIN__) && !defined(_WIN32)
	static type get_random (size_t length_in_bytes) {
		if (!m_reader.good())
			throw std::runtime_error("some error occured while reading from random number generator device");

		m_reader.rdbuf()->pubsetbuf(nullptr, 0); // stop buffering data
		type random = 0;
		unsigned char read;
		size_t size_of_random = 0;
		while (size_of_random < length_in_bytes) {
			read = (unsigned char)m_reader.get();
			random <<= (sizeof(read) * 8);
			random += (int)read;
			size_of_random += (sizeof(read));
		}
		return random;
	}
#else
	static type get_random (size_t length_in_bytes) {
		type random = 0;
		HCRYPTPROV prov;
		CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_FULL, 0);
		CryptGenRandom(prov, sizeof(random), (BYTE *)&random);
		return random;
	}
#endif
};


#if !defined(__CYGWIN__) && !defined(_WIN32)
template <typename type>
std::ifstream c_random_generator<type>::m_reader (

RANDOM_DEVICE, ios_base::in);
#endif

#endif //CRYPTO_RANDOM_GENERATOR_HPP
