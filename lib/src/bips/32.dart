


class BIP32 {

/// Ranges from 128bit to 256bit
final String bip39Seed;

void generateMasterPrivateKey(){
  var hashOfBip39Seed = HMACSHA512HashFunction(bip39Seed);

var left256Bits = hashOfBip39Seed[0 to 255];
var right256Bits = hashOfBip39Seed[0 to 255];

/// 256 bits
var MasterPrivateKeym = left256Bits;
/// 256 bits
var MasterChainCodec = right256Bits;

/// 256 bits
var MasterPublicKeyM = generatePublicKeyUsingPrivateKey(MasterPrivateKeym);

}


void childKeyDerivation(){
  
}

  generatePublicKeyUsingPrivateKey(masterPrivateKeym) {}


}