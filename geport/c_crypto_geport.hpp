/* See the LICENSE.txt for license information */

#ifndef CRYPTO_C_CRYPTO_GEPORT_H
#define CRYPTO_C_CRYPTO_GEPORT_H
#include <boost/multiprecision/cpp_int.hpp>
#include <string>
#include "../external/c_random_generator.hpp"
#include <limits>

using namespace boost::multiprecision;
using std::string;
using std::numeric_limits;

template <size_t hash_length,
        size_t log2_hash_length,
        number<cpp_int_backend<hash_length * 2, hash_length * 2, unsigned_magnitude, unchecked, void>> hash_function (const string &)>
class c_crypto_geport {
public:
    typedef number<cpp_int_backend<hash_length * 2, hash_length * 2, unsigned_magnitude, unchecked, void>> long_type;
    typedef long_type public_key_t;
    static constexpr size_t signature_or_private_key_length = hash_length + log2_hash_length;
    static_assert(1 << log2_hash_length >= hash_length, "invalid lengths provided");

    struct signature_t {
        size_t pop_count; // this MUST be able to store log2(hash_size) number
        long_type Signature[signature_or_private_key_length];
    };

    static_assert(numeric_limits<size_t>::max() >= log2_hash_length, "log2(hash length) seems to be too huge");

private:
    static c_random_generator<long_type> rd_gen;

    static long_type generate_hash (const string &value) { return hash_function(value); }

    static long_type generate_hash (const long_type &value) { return generate_hash(string(value)); }

    static void join_hash (long_type &a, const long_type &b) {
      a <<= hash_length;
      a += b;
      a = generate_hash(a);
    }

    static size_t pop_count_in_hash (long_type value) {
      size_t counter = 0;
      for (size_t i = 0; i < hash_length; ++i, value >>= 1) {
        if (value & 1)
          ++counter;
      }
      return counter;
    }

public:
    c_crypto_geport () = default;

    static public_key_t generate_keypair (long_type Private_key[signature_or_private_key_length]) {
      for (size_t i = 0; i < signature_or_private_key_length; ++i)
        Private_key[i] = rd_gen.get_random((signature_or_private_key_length) / 8);

      public_key_t public_key = generate_public_key(Private_key);

      return public_key;
    }

    static public_key_t generate_public_key (const long_type Private_key[signature_or_private_key_length]) {
      public_key_t public_key = 0;
      for (size_t i = 0; i < signature_or_private_key_length; ++i)
        join_hash(public_key, generate_hash(generate_hash(Private_key[i])));

      return public_key;
    }

    static signature_t sign (const string &msg, const long_type Private_key[signature_or_private_key_length]) {
      long_type hashed_msg = generate_hash(msg);

      signature_t signature;

      signature.pop_count = pop_count_in_hash(hashed_msg);
      long_type hashed_private_key;


      if (signature.pop_count > hash_length / 2) {
        hashed_msg = ~hashed_msg;
      }

      for (size_t i = 0; i < hash_length; ++i) {
        hashed_private_key = generate_hash(Private_key[i]);
        if (hashed_msg & (1 << i))
          signature.Signature[i] = Private_key[i];
        else
          signature.Signature[i] = hashed_private_key;
      }

      for (size_t i = hash_length; i < signature_or_private_key_length; ++i) {
        hashed_private_key = generate_hash(Private_key[i]);
        if (signature.pop_count & (1 << i))
          signature.Signature[i] = Private_key[i];
        else
          signature.Signature[i] = hashed_private_key;
      }

      return signature;
    }

    static bool verify_sign (const string &msg, const signature_t &signature, const public_key_t &pub_key) {
      long_type hashed_msg = generate_hash(msg), tmp;
      long_type generated_public_key = 0;
      long_type hashed_signature;

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