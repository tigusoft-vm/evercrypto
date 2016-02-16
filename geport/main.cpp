#include <iostream>
#include <string>
#include <list>
#include <thread>
#include <mutex>
#include <atomic>
#include "c_crypto_geport.hpp"
#include "../external/sha_src/sha256.hpp"
#include "../external/sha_src/sha512.hpp"
#include <fstream>
#include <streambuf>
#include <memory>
#include <chrono>
#include <iomanip>

#ifdef bool // some C files included to funky stuff like that, we undo it
	#undef bool
	#undef true
	#undef false
#endif

using std::cout;
using std::cerr;
using std::cin;
using std::string;
using std::endl;
using std::list;
using std::thread;
using std::mutex;
using std::atomic;
using std::ifstream;
using std::ofstream;
using std::runtime_error;
using std::unique_ptr;

typedef number<cpp_int_backend<512 * 2, 512 * 2, unsigned_magnitude, unchecked, void>> long_type;
typedef c_crypto_geport<512, 9, sha512<string>> c_crypto_geport_def;

void show_help () {
	cout << "-g\t--gen-key [priv_key pub_key]\t\t\tgenerate keypair and write it to given files" << endl;
	cout << "-s\t--sign [file priv_key sig_file]\t\t\tcreate signature of given file" << endl;
	cout << "-c\t--check-signature [file signature pub_key]\tcheck correctness of given signature" << endl;
	cout <<
	"-v\t--verify-public-key [priv_key pub_key]\t\tcheck whether given public key is corresponding with given private key" <<
	endl;
	cout << "\t--gen-sha512 [file]" << endl;
	cout << "\t--gen-sha256 [file]" << endl;
	cout << "\t--gen-sha512-dec [file]" << endl;
	cout << "\t--gen-sha256-dec [file]" << endl;
	cout << "\t--version" << endl;
	cout << "-f\t--file-to-string [file]\t\t\t\tfor debug purposes only" << endl;
	cout << "\t--help\t\t\t\t\t\tshow this manual" << endl;
	cout << "\t--yes\t\t\t\t\t\tat the end of command, skip questions answering \"yes\"" << endl;
}

void show_preamble () {
	cerr << "============================================\n";
	cerr << "The geport testing program\n";
	cerr << "============================================\n";
	cerr << "WARNING: This is a very early pre-alpha, do not use this!\n";
	cerr << "Do not even run this at any real user, it likely contains errors, UBs, or exploits!\n";
	cerr << "Test on separate user/environment until we have a tested version.\n";
	cerr << "============================================\n\n";
}

string file_to_string (const string &filename) {
	ifstream file(filename);
	if (!file.good()) {
		throw runtime_error("error while opening a file [" + filename + "]");
	}

	string result((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	file.close();
	return result;
}

c_crypto_geport_def::private_key_t get_private_key_from_file (const string &filename) {
	ifstream file(filename);
	if (!file.good()) {
		throw runtime_error("error while opening a file [" + filename + "]");
	}

	c_crypto_geport_def::private_key_t result;
	for (size_t i = 0; i < c_crypto_geport_def::signature_or_private_key_length; ++i) {
		if (file.eof()) {
			throw runtime_error(string("error while reading a file [") + filename + "] : end of file");
		}
		file >> result[i];
	}

	return result;
}

c_crypto_geport_def::signature_t get_signature_from_file (const string &filename) {
	ifstream file(filename);
	if (!file.good()) {
		throw runtime_error("error while opening a file [" + filename + "]");
	}

	c_crypto_geport_def::signature_t result;
	file >> result.pop_count;
	for (size_t i = 0; i < c_crypto_geport_def::signature_or_private_key_length; ++i) {
		if (file.eof()) {
			throw runtime_error(string("error while reading a file [") + filename + string("] : end of file"));
		}
		file >> result.Signature[i];
	}

	return result;
}

c_crypto_geport_def::public_key_t get_public_key_from_file (const string &filename) {
	ifstream file(filename);
	if (!file.good()) {
		throw runtime_error("error while opening a file [" + filename + "]");
	}

	string sub_result;
	file >> sub_result;
	return c_crypto_geport_def::public_key_t(sub_result);
}

void generate_key (const string &priv_key_filename, const string &pub_key_filename, bool skip = false) {
	if (!skip) {
		cout << "This operation will overwrite files [" << priv_key_filename << "], [" << pub_key_filename <<
		"]\nAre you sure you want to continue? [Y/n] ";
		char decision;
		cin >> decision;
		if (tolower(decision) != 'y') {
			cout << "aborted\n";
			return;
		}
	}

	ofstream priv_file(priv_key_filename, ofstream::out | ofstream::trunc);
	ofstream pub_file(pub_key_filename, ofstream::out | ofstream::trunc);

	if (!priv_file.good()) {
		throw runtime_error("error while opening a file [" + priv_key_filename + "]");
	}
	if (!priv_file.good()) {
		throw runtime_error("error while opening a file [" + pub_key_filename + "]");
	}

	cerr << "PLEASE NOTICE, THAT PRIVATE KEY IS WRITTEN TO FILE IN PLAINTEXT FORM" << endl;
	cerr << "YOU SHOULD ENCRYPT IT USING FOR EXAMPLE PGP" << endl;

	c_crypto_geport_def::long_type Private_key[c_crypto_geport_def::signature_or_private_key_length];
	auto keypair = c_crypto_geport_def::generate_keypair();

	for (size_t i = 0; i < c_crypto_geport_def::signature_or_private_key_length; ++i) {
		priv_file << keypair.private_key[i] << '\n';
	}
	pub_file << keypair.public_key << '\n';
}

void sign (const string &filename,
		const string &priv_key_filename,
		const string &signature_filename,
		bool skip = false) {

	if (!skip) {
		cout << "This operation will overwrite file [" << signature_filename <<
		"]\nAre you sure you want to continue? [Y/n] ";
		char decision;
		cin >> decision;
		if (tolower(decision) != 'y') {
			cout << "aborted\n";
			return;
		}
	}

	ofstream signature_file(signature_filename, ofstream::out | ofstream::trunc);
	if (!signature_file.good()) {
		throw runtime_error("error while opening a file [" + signature_filename + "]");
	}

	c_crypto_geport_def::signature_t signature =
			c_crypto_geport_def::sign(file_to_string(filename), get_private_key_from_file(priv_key_filename));

	signature_file << signature.pop_count << '\n';
	for (size_t i = 0; i < c_crypto_geport_def::signature_or_private_key_length; ++i) {
		signature_file << signature.Signature[i] << '\n';
	}
}

void check_signature (const string &filename, const string &signature_filename, const string &pub_key_filename) {
	bool is_ok = c_crypto_geport_def::verify_sign(file_to_string(filename),
												  get_signature_from_file(signature_filename),
												  get_public_key_from_file(pub_key_filename));

	if (is_ok)
		cout << "signature is OK\n";

	else
		cout << "signature is WRONG\n";
}

void check_public_key (const string &priv_key_filename, const string &pub_key_filename) {
	bool is_ok = c_crypto_geport_def::generate_public_key(get_private_key_from_file(priv_key_filename)) ==
				 get_public_key_from_file(pub_key_filename);
	if (is_ok)
		cout << "public key is OK\n";
	else
		cout << "public key is WRONG\n";
}

string get_current_time () {
	auto in_time_t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	std::stringstream ss;

	ss << "(time put not implemented)";
	//  ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X"); // does not work on Debian 8? Needs gcc >= 5

	return ss.str();
}

int main (int argc, const char *argv[]) {
	ios_base::sync_with_stdio(false);
	const string version = "v0.1 beta, 10.12.2015";

	if (argc > 1) {
		if (string(argv[1]) == string("--dev")) {
			std::cout << "Foooo" << std::endl;
			devel_test();
			return 0;
		}
	}

	if (argc < 2) {
		cout << "use --help to show manual\n";
		return 0;
	}

	string command(argv[1]);

	if (command == "--help") {
		show_preamble();
		show_help();

	} else if (command == "--gen-key" || command == "-g") {
		if (argc < 4) {
			cout << "specify output file for private nd for public key\n";
			return 0;
		}

		string priv(argv[2]), pub(argv[3]);
		generate_key(priv, pub, (argc > 4 && !strcmp(argv[4], "--yes")));

	} else if (command == "--sign" || command == "-s") {
		if (argc < 5) {
			cout << "specify file to sign, private key and output file for signature\n";
			return 0;
		}

		string file(argv[2]), priv(argv[3]), signature(argv[4]);
		sign(file, priv, signature, (argc > 5 && !strcmp(argv[5], "--yes")));

	} else if (command == "--check-signature" || command == "-c") {
		if (argc < 5) {
			cout << "specify file you want to check, signature and public key\n";
			return 0;
		}

		string file(argv[2]), signature(argv[3]), pub_key(argv[4]);
		check_signature(file, signature, pub_key);

	} else if (command == "--gen-sha512") {
		if (argc < 3) {
			cout << "specify file you want to check\n";
			return 0;
		}

		string file(argv[2]);
		cout << sha512<string>(file_to_string(file)) << "  " << file << '\n';

	} else if (command == "--gen-sha256") {
		if (argc < 3) {
			cout << "specify file you want to check\n";
			return 0;
		}

		string file(argv[2]);
		cout << sha256<string>(file_to_string(file)) << "  " << file << '\n';

	} else if (command == "--gen-sha512-dec") {
		if (argc < 3) {
			cout << "specify file you want to check\n";
			return 0;
		}

		string file(argv[2]);
		cout <<
		sha512<number<cpp_int_backend<512 * 2, 512 * 2, unsigned_magnitude, unchecked, void>>>(file_to_string(file)) <<
		"  " << file << '\n';

	} else if (command == "--gen-sha256-dec") {
		if (argc < 3) {
			cout << "specify file you want to check\n";
			return 0;
		}

		string file(argv[2]);
		cout <<
		sha256<number<cpp_int_backend<256 * 2, 256 * 2, unsigned_magnitude, unchecked, void>>>(file_to_string(file)) <<
		"  " << file << '\n';

	} else if (command == "--file-to-string" || command == "-f") {
		if (argc < 3) {
			cout << "specify file you want to check\n";
			return 0;
		}

		string file(argv[2]);
		cout << file_to_string(file);

	} else if (command == "--verify-public-key" || command == "-v") {
		if (argc < 4) {
			cout << "specify private and public key\n";
			return 0;
		}

		string private_key(argv[2]), public_key(argv[3]);
		check_public_key(private_key, public_key);

	} else if (command == "--version") {
		cout << version << endl;

	} else {
		cout << "no such command, use --help to show manual\n";
		return 0;
	}
}
