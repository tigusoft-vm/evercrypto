#include <iostream>
#include <string>
#include <boost/multiprecision/cpp_int.hpp>
#include "c_random_generator.hpp"

using std::cin;
using std::cout;
using std::stoi;
using namespace boost::multiprecision;

typedef number<cpp_int_backend<0, 512 * 512 * 10, unsigned_magnitude, checked, void>> long_type;

int main (int argc, char *argv[]) {
  if (argc <= 1) {
    cout << "please define number of random bytes you want\n";
    return 0;
  }

  int bytes = 0;

  try { bytes = stoi(argv[1]); }
  catch (...) {
    cout << "please define valid number of bytes\n";
    return 0;
  }

  cout << c_random_generator<long_type>::get_random(bytes);
  return 0;
}