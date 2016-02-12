/* COMPILE IT WITH
 * -pipe -Ofast -std=c++11 -pthread
 */

#include <iostream>
#include <string>
#include <list>
#include <thread>
#include <mutex>
#include <atomic>
#include <boost/multiprecision/cpp_int.hpp>
#include "c_crypto_geport.hpp"
#include "../external/random_generator/c_random_generator.hpp"
#include "../external/sha_src/sha256.hpp"
#include "../external/sha_src/sha512.hpp"

using std::cout;
using std::cin;
using std::string;
using std::endl;
using std::list;
using std::thread;
using std::mutex;
using std::atomic;
using std::stoi;
using namespace boost::multiprecision;

typedef number<cpp_int_backend<0, 512 * 2, unsigned_magnitude, unchecked, void>> long_type;
typedef c_crypto_geport<512, 9, sha512<string>> c_crypto_geport_def;

atomic<size_t> tests_counter(0);
atomic<bool> is_wrong(false);
int number_of_threads;

int get_rand () { return c_random_generator<int>::get_random(sizeof(int)); }

string generate_random_string (size_t length) {
  auto generate_random_char = [] () -> char {
      const char Charset[] = "0123456789"
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              "abcdefghijklmnopqrstuvwxyz";
      const size_t max_index = (sizeof(Charset) - 1);
      return Charset[rand() % max_index];
  };
  string str(length, 0);
  generate_n(str.begin(), length, generate_random_char);
  return str;
}

string generate_different_string (const string &msg) {
  string ret(msg);
  auto random = get_rand() % 10;

  switch (random) {
    case 0:
      ret += ' ';
      break;
    case 1:
      ret.erase(0, 1);
      break;
    case 2:
      if (ret[ret.size() / 2] != 'a')
        ret[ret.size() / 2] = 'a';
      else
        ret[ret.size() / 2] = 'b';
      break;
    case 3:
      ret = ret.substr(0, ret.size() / 2) + ' ' + ret.substr(ret.size() / 2, ret.size() / 2);
      break;
    case 4:
      ret = "";
      break;
    case 5:
      ret = " ";
      break;
    case 6:
      ret = generate_random_string(ret.size());
      break;
    case 7:
      ret = ret.substr(0, ret.size() / 2) + generate_random_string(50) + ret.substr(ret.size() / 2, ret.size() / 2);
      break;
    case 8:
      ret = generate_random_string(500);
      break;
    case 9:
      ret = generate_random_string(2);
      break;
    default:
      break;
  }

  if (msg == ret) return generate_different_string(msg);
  return ret;
}

bool check_equality_of_signature (const c_crypto_geport_def::signature_t &a, const c_crypto_geport_def::signature_t &b) {
  if (a.pop_count != b.pop_count)
    return false;

  for (size_t i = 0; i < c_crypto_geport_def::signature_or_private_key_length; ++i) {
    if (a.Signature[i] != b.Signature[i])
      return false;
  }

  return true;
}

c_crypto_geport_def::signature_t generate_different_signature (const c_crypto_geport_def::signature_t &signature) {
  c_crypto_geport_def::signature_t ret = signature;
  auto random = get_rand() % 11;

  switch (random) {
    case 0:
      ret.Signature[get_rand() % (c_crypto_geport_def::signature_or_private_key_length)] -= (get_rand() % 10000000L) + 1;
      break;
    case 1:
      ret.Signature[get_rand() % (c_crypto_geport_def::signature_or_private_key_length)] += 1;
      break;
    case 2:
      ret.pop_count += 1;
      break;
    case 3:
      ret.pop_count = ~ret.pop_count;
      break;
    case 4:
      ret.pop_count = 512 - ret.pop_count;
      break;
    case 5:
      ret.Signature[0] = ~ret.Signature[0];
      break;
    case 6:
      ret = c_crypto_geport_def::signature_t();
      break;
    case 7:
      ret.pop_count = 0;
      break;
    case 8:
      ret.pop_count = 1;
      break;
    case 9:
      ret.pop_count = 0;
      for (auto &v : ret.Signature)
        v = 0;
      break;
    case 10:
      ret.pop_count = 0;
      break;
    default:
      break;
  }

  if (check_equality_of_signature(ret, signature))
    return generate_different_signature(signature);

  return ret;
}

c_crypto_geport_def::public_key_t generate_different_public_key (c_crypto_geport_def::public_key_t &public_key) {
  c_crypto_geport_def::public_key_t ret = public_key;
  auto random = get_rand() % 6;

  switch (random) {
    case 0:
      ret += (get_rand() % 10000000L) + 1;
      break;
    case 1:
      ret  += 1;
      break;
    case 2:
      ret = ~ret;
      break;
    case 3:
      ret = ret / 2;
      break;
    case 4:
      ret = 0;
      break;
    case 5:
      ret = 1;
      break;
    default:
      break;
  }

  if (ret == public_key) return generate_different_public_key(public_key);
  else return ret;
}

void random_generator_test (size_t size) {
  c_random_generator<long_type> generator;
  list<long_type> set;

  for (size_t i = 0; i < size; ++i)
    set.push_back(generator.get_random(33));

  size_t counter = set.size();
  set.unique();
  cout << "there was " << (counter - set.size()) << " collisions of random generator on " << size << " tests" << endl;
}

void print_signed_msg (const c_crypto_geport_def::signature_t &signature, const c_crypto_geport_def::public_key_t &public_key) {
  cout << "  public_key: " << public_key << endl << "  pop count: " << signature.pop_count << endl <<
  "  sig values:" << endl;
  for (auto &in : signature.Signature)
    cout << "    " << in << '\n';
}

void correctness_test (size_t size) {
  size_t jump = 100;
  auto keypair = c_crypto_geport_def::generate_keypair();
  c_crypto_geport_def::public_key_t different_public_key;

  string message, different_message;
  c_crypto_geport_def::signature_t signature, different_signature;

  for (size_t i = 0; i < size; ++i, ++tests_counter) {
    message = generate_random_string((rand() % 50) + 5); // TODO
    signature = c_crypto_geport_def::sign(message, keypair.private_key);

    if (!c_crypto_geport_def::verify_sign(message, signature, keypair.public_key)) {
      is_wrong = true;
      cout << "-------------------------------------------------------------\n";
      cout << "veryfing correct message gone wrong" << endl;
      cout << "message: " << message << endl << "signature:\n";
      print_signed_msg(signature, keypair.public_key);
      return;
    }

    for (size_t counter = 0; counter < 20; ++counter) {
      different_signature = generate_different_signature(signature);
      different_message = generate_different_string(message);
      different_public_key = generate_different_public_key(keypair.public_key);

      if (c_crypto_geport_def::verify_sign(different_message, signature, keypair.public_key)) {
        is_wrong = true;
        cout << "-------------------------------------------------------------\n";
        cout << "veryfing wrong message gone wrong" << endl;
        cout << "message: " << message << endl;
        cout << "wrong message: " << different_message << endl << "signature: \n";
        print_signed_msg(signature, keypair.public_key);
        return;
      }

      if (c_crypto_geport_def::verify_sign(message, different_signature, keypair.public_key)) {
        is_wrong = true;
        cout << "-------------------------------------------------------------\n";
        cout << "veryfing correct message with wrong signature is OK" << endl;
        cout << "message: " << message << endl << "wrong signature:\n";
        print_signed_msg(signature, keypair.public_key);
        return;
      }

      if (c_crypto_geport_def::verify_sign(message, different_signature, different_public_key)) {
        cout << "---I'm not sure if this error definitely shouldn't happened---\n";
        cout << "veryfing correct message with wrong signature AND wrong public key is OK" << endl;
        cout << "message: " << message << endl << "wrong signature:\n";
        print_signed_msg(signature, keypair.public_key);
      }
    }

    if (tests_counter % jump == 0) {
      cout << tests_counter / jump + 1 << " / " << size * number_of_threads / jump << endl;
    }
  }
}

void start_testing () {
  size_t rgt_size = 10000;
  size_t c_size = 10000;
  random_generator_test(rgt_size);
  correctness_test(c_size);
}

int main (int argc, char *argv[]) {
  ios_base::sync_with_stdio(false);

//  if (argc <= 1) {
//    cout << "please define number of threads to run test\n";
//    return 0;
//  }

  try { number_of_threads = 4; }
  catch (...) {
    cout << "please define correct number of threads to run test\n";
    return 0;
  }

  if (number_of_threads <= 0) {
    cout << "please define correct number of threads to run test\n";
    return 0;
  }

  list<thread> Threads;

  for (int i = 0; i < number_of_threads; ++i)
    Threads.emplace_back(start_testing);

  for (auto &t : Threads)
    t.join();

  if (!is_wrong)
    cout << "all correctness tests passed!\n";

  return 0;
}
