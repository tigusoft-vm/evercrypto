#ifndef CRYPTO_C_CRYPTO_GEPORT_H
#define CRYPTO_C_CRYPTO_GEPORT_H
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include "../external/random_generator/c_random_generator.hpp"
#include "../external/sha_src/sha512.hpp"
#include <limits>

#include <memory>

#include "../external/sha_src/sha256.hpp"
#include "../external/sha_src/sha512.hpp"

#ifdef bool // some C files included to funky stuff like that, we undo it
	#undef bool
	#undef true
	#undef false
#endif

using namespace boost::multiprecision;
using std::string;
using std::numeric_limits;

using std::unique_ptr; ///< @TODO

// === FIXES ===
// TODO (move me)
// this is due to enter C++14
// http://stackoverflow.com/questions/7038357/make-unique-and-perfect-forwarding
template <typename T, typename... Args>
std::unique_ptr<T> make_unique (Args &&... args) {
	return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}



// === sign ===

class c_evercrypto_sign { };

class c_evercrypto_sign_geport_base : public c_evercrypto_sign {
};

template <size_t hash_length, size_t log2_hash_length, string hash_function (const string &)>
struct c_evercrypto_sign_geport : public c_evercrypto_sign_geport_base {
	public:
		int data[hash_length];
		int data2[log2_hash_length];
	// TODO change to real geport
};

// === pubkey ===

class c_evercrypto_pubkey { };

class c_evercrypto_pubkey_geport_base : public c_evercrypto_pubkey {
};

template <size_t hash_length, size_t log2_hash_length, string hash_function (const string &)>
struct c_evercrypto_pubkey_geport : public c_evercrypto_pubkey_geport_base {
	typedef number<cpp_int_backend<hash_length * 2, hash_length * 2, unsigned_magnitude, unchecked, void>> long_type;

	long_type pubkey_data;
};

// === privkey ===

class c_evercrypto_privkey { };

class c_evercrypto_privkey_geport_base : public c_evercrypto_privkey {
};

template <size_t hash_length, size_t log2_hash_length, string hash_function (const string &)>
struct c_evercrypto_privkey_geport : public c_evercrypto_privkey_geport_base {
	typedef number<cpp_int_backend<hash_length * 2, hash_length * 2, unsigned_magnitude, unchecked, void>> long_type;

	long_type privkey_data;
};

// === engine ===

class c_evercrypto_engine {
	public:
	virtual unique_ptr <c_evercrypto_pubkey> load_pubkey();
};

unique_ptr <c_evercrypto_pubkey> c_evercrypto_engine::load_pubkey() {
	ifstream file("test.dat");
	int kind = -1;
	file >> kind;

	// TODO enum
	// TODO check errors etc

	if (kind == 1) { // geport
		int kind_hash = -1;
		file >> kind_hash;

		if (kind_hash == 3) { // sha512
			// @TODO make_unique
			auto ret = new c_evercrypto_pubkey_geport<512,9, sha512<std::string> > ();
			c_evercrypto_pubkey * any = ret;



			
			return unique_ptr<c_evercrypto_pubkey>(any);
		}

	}

	throw 42;

}


class c_evercrypto_engine_geport_base : public c_evercrypto_engine {
};

template <size_t hash_length, size_t log2_hash_length, string hash_function (const string &)>
struct c_evercrypto_engine_geport : public c_evercrypto_engine_geport_base {
};


// ===


void devel_test() {
	std::cerr << "devel_test" << std::endl;

	unique_ptr<c_evercrypto_pubkey> x;
}




/*

// the engine of evercrypto, providing usable higher level functions:
class c_evercrypto {
	public:
		bool check_sign(const PUBKEY,  const SIGNATURE &, const MESSAGE &) {
			// using: static bool verify_sign (const string &msg, const signature_t &signature, const public_key_t &pub_key) {

			bool ok = 0;

			if (rtti PUBKEY ... == geport_sha512) {
				if (rtti MESSAGE == geport_sha512) {
					ok = c_crypto_geport<SHA512>::verify_sign(MESSAGE, SIGNATURE, ...)
				}
			}

			return 1;
		}

		bool generate_keypair();
		SIGNATUR sign(const PRIVKEY &, const MESSAGE &);

		bool check_sign(const PUBKEY_FINGERPRIT &, const SIGNATURE &, const MESSAGE &) { return check_sign( find_pubkey_by_hash(PUBKEY_FINGERPRIT) , SIGNATURE , MESSAGE ); }

};

void downloader_action() {
	auto x = evercrypto.load_pubkey( data_stream ); // e.g.: will be instance of c_evercrypto_pubkey_geport<SHA512> (in runtime)
	auto y = evercrypto.load_signature( data_sream ); // e.g. c_evercrypto_sign<SHA512>
	bool ok = check_sign(x,y);
}



*/



template <size_t hash_length, size_t log2_hash_length, string hash_function (const string &)>
class c_crypto_geport {
public:
	typedef number<cpp_int_backend<hash_length * 2, hash_length * 2, unsigned_magnitude, unchecked, void>> long_type;

	static constexpr size_t signature_or_private_key_length = hash_length + log2_hash_length;
	static_assert(1 << log2_hash_length >= hash_length, "invalid lengths provided");
	static_assert(numeric_limits<size_t>::max() >= log2_hash_length, "log2(hash length) seems to be too huge");

	struct signature_t {
		size_t pop_count; // this MUST be able to store log2(hash_size) number
		std::array<long_type, signature_or_private_key_length> Signature;
	};

	typedef long_type public_key_t;
	typedef long_type hash_t;
	typedef std::array<long_type, signature_or_private_key_length> private_key_t;

	struct keypair_t {
		public_key_t public_key;
		private_key_t private_key;
	};

private:
	static c_random_generator<long_type> rd_gen;

	static hash_t generate_hash (const string &value) {
		string hash = hash_function(value);
		if (hash.at(0) != '0' || hash.at(1) != 'x') {
			hash = "0x" + hash;
		}
		return long_type(hash);
	}

	static hash_t generate_hash (const long_type &value) { return generate_hash(string(value)); }

	static void join_hash (hash_t &a, const hash_t &b) {
		//      a <<= hash_length;
		//      a += b;
		//      a = generate_hash(a);
		a = generate_hash(a);
		a ^= b;
		a = generate_hash(a);
	}

	static size_t pop_count_in_hash (hash_t value) {
		size_t counter = 0;
		for (size_t i = 0; i < hash_length; ++i, value >>= 1) {
			if (value & 1)
				++counter;
		}
		return counter;
	}

public:
	c_crypto_geport () = default;

	static keypair_t generate_keypair () {
		keypair_t keypair;
		for (size_t i = 0; i < signature_or_private_key_length; ++i)
			keypair.private_key[i] = rd_gen.get_random((signature_or_private_key_length) / 8);

		keypair.public_key = generate_public_key(keypair.private_key);

		return keypair;
	}

	static public_key_t generate_public_key (const private_key_t &private_key) {
		public_key_t public_key = 0;
		for (size_t i = 0; i < signature_or_private_key_length; ++i)
			join_hash(public_key, generate_hash(generate_hash(private_key[i])));

		return public_key;
	}

	static signature_t sign (const string &msg, const private_key_t &private_key) {
		hash_t hashed_msg = generate_hash(msg);
		signature_t signature;

		signature.pop_count = pop_count_in_hash(hashed_msg);
		hash_t hashed_private_key;


		if (signature.pop_count > hash_length / 2) {
			hashed_msg = ~hashed_msg;
		}

		for (size_t i = 0; i < hash_length; ++i) {
			hashed_private_key = generate_hash(private_key[i]);
			if (hashed_msg & (1 << i))
				signature.Signature[i] = private_key[i];
			else
				signature.Signature[i] = hashed_private_key;
		}

		for (size_t i = hash_length; i < signature_or_private_key_length; ++i) {
			hashed_private_key = generate_hash(private_key[i]);
			if (signature.pop_count & (1 << i))
				signature.Signature[i] = private_key[i];
			else
				signature.Signature[i] = hashed_private_key;
		}

		return signature;
	}

	static bool verify_sign (const string &msg, const signature_t &signature, const public_key_t &pub_key) {
		hash_t hashed_msg = generate_hash(msg), tmp;
		public_key_t generated_public_key = 0;
		hash_t hashed_signature;

		if (signature.pop_count != pop_count_in_hash(hashed_msg))
			return false;


		if (signature.pop_count > hash_length / 2) {
			hashed_msg = ~hashed_msg;
		}

		for (size_t i = 0; i < hash_length; ++i) {
			hashed_signature = generate_hash(signature.Signature[i]);
			if (hashed_msg & (1 << i))
				tmp = hashed_signature;
			else
				tmp = signature.Signature[i];

			join_hash(generated_public_key, generate_hash(tmp));
		}

		for (size_t i = hash_length; i < signature_or_private_key_length; ++i) {
			hashed_signature = generate_hash(signature.Signature[i]);
			if (signature.pop_count & (1 << i))
				tmp = hashed_signature;
			else
				tmp = signature.Signature[i];

			join_hash(generated_public_key, generate_hash(tmp));
		}
		return (generated_public_key == pub_key);
	}
};


#endif //CRYPTO_C_CRYPTO_GEPORT_H
