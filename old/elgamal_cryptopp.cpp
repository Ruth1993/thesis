#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/elgamal.h>
using CryptoPP::ElGamal;
using CryptoPP::ElGamalKeys;

#include <cryptopp/cryptlib.h>
using CryptoPP::DecodingResult;

int main(int argc, char* argv[])
{
    ////////////////////////////////////////////////
    // Generate keys
	/**
    AutoSeededRandomPool rng;

    cout << "Generating private key. This may take some time..." << endl;

    ElGamal::Decryptor decryptor;
    decryptor.AccessKey().GenerateRandomWithKeySize(rng, 512);
    const ElGamalKeys::PrivateKey& privateKey = decryptor.AccessKey();

    ElGamal::Encryptor encryptor(decryptor);
    const PublicKey& publicKey = encryptor.AccessKey();

    ////////////////////////////////////////////////
    // Secret to protect
    static const int SECRET_SIZE = 16;
    SecByteBlock plaintext( SECRET_SIZE );
    memset( plaintext, 'A', SECRET_SIZE );

    ////////////////////////////////////////////////
    // Encrypt

    // Now that there is a concrete object, we can validate
    assert( 0 != encryptor.FixedMaxPlaintextLength() );
    assert( plaintext.size() <= encryptor.FixedMaxPlaintextLength() );

    // Create cipher text space
    size_t ecl = encryptor.CiphertextLength( plaintext.size() );
    assert( 0 != ecl );
    SecByteBlock ciphertext( ecl );

    encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );

    ////////////////////////////////////////////////
    // Decrypt

    // Now that there is a concrete object, we can check sizes
    assert( 0 != decryptor.FixedCiphertextLength() );
    assert( ciphertext.size() <= decryptor.FixedCiphertextLength() );

    // Create recovered text space
    size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
    assert( 0 != dpl );
    SecByteBlock recovered( dpl );

    DecodingResult result = decryptor.Decrypt( rng, ciphertext, ciphertext.size(), recovered );

    // More sanity checks
    assert( result.isValidCoding );
    assert( result.messageLength <= decryptor.MaxPlaintextLength( ciphertext.size() ) );

    // At this point, we can set the size of the recovered
    //  data. Until decryption occurs (successfully), we
    //  only know its maximum size
    recovered.resize( result.messageLength );

    // SecByteBlock is overloaded for proper results below
    assert( plaintext == recovered );

    // If the assert fires, we won't get this far.
    if(plaintext == recovered)
        cout << "Recovered plain text" << endl;
    else
        cout << "Failed to recover plain text" << endl;

    return !(plaintext == recovered);
	*/
	
	cout << "test" << endl;
	return 0;
}