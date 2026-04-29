#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <map>
#include <algorithm>
#include <iomanip>



int modInverse(int a, int n) {
    a = a % n;
    for (int x = 1; x < n; x++)
        if ((a * x) % n == 1)
            return x;
    return -1; 
}


std::string simpleSubstitution(std::string text, std::string key, bool encrypt) {
    std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
    std::string res = "";
    for (char c : text) {
        if (!isalpha(c)) { 
            res += c;
            continue; 
        }
        
        bool isUpper = isupper(c);
        char lowerC = tolower(c);
        
        if (encrypt) {
            char encChar = key[lowerC - 'a'];
            res += isUpper ? toupper(encChar) : encChar;
        } else {
            char decChar = alphabet[key.find(lowerC)];
            res += isUpper ? toupper(decChar) : decChar;
        }
    }
    return res;
}

// 2. Аффинный шифр
std::string affineCipher(std::string text, int a, int b, bool encrypt) {
    std::string res = "";
    int n = 26;
    int a_inv = encrypt ? 0 : modInverse(a, n);
    
    if (!encrypt && a_inv == -1) {
        return "Error: a and n are not coprime. Decryption impossible.";
    }
    
    for (char c : text) {
        if (!isalpha(c)) { 
            res += c; 
            continue; 
        }
        
        bool isUpper = isupper(c);
        int x = tolower(c) - 'a';
        int y = 0;
        
        if (encrypt) {
            y = (a * x + b) % n;
        } else {
            
            y = (a_inv * (x - b)) % n;
            y = (y + n) % n; 
        }
        
        res += (char)(y + (isUpper ? 'A' : 'a'));
    }
    return res;
}


std::string affineRecurrent(std::string text, int a1, int b1, int a2, int b2, bool encrypt) {
    std::string res = "";
    int n = 26;
    std::vector<int> a = {a1, a2};
    std::vector<int> b = {b1, b2};
    
    int letter_idx = 0;
    
    for (char c : text) {
        if (!isalpha(c)) { 
            res += c; 
            continue; 
        }
        
        
        if (letter_idx >= 2) {
            a.push_back((a[letter_idx - 1] * a[letter_idx - 2]) % n);
            b.push_back((b[letter_idx - 1] + b[letter_idx - 2]) % n);
        }
        
        bool isUpper = isupper(c);
        int x = tolower(c) - 'a';
        int y = 0;
        
        if (encrypt) {
            y = (a[letter_idx] * x + b[letter_idx]) % n;
        } else {
            int a_inv = modInverse(a[letter_idx], n);
            if (a_inv == -1) {
                res += '?'; 
            } else {
                y = (a_inv * (x - b[letter_idx])) % n;
                y = (y + n) % n; 
            }
        }
        
        res += (char)(y + (isUpper ? 'A' : 'a'));
        letter_idx++; 
    }
    return res;
}
void cryptanalysisSubstitution(std::string ciphertext) {
    
    std::map<char, int> freq;
    for (char c : ciphertext) if (isalpha(c)) freq[tolower(c)]++;

   
    std::vector<std::pair<char, int>> sortedFreq(freq.begin(), freq.end());
    sort(sortedFreq.begin(), sortedFreq.end(), [](const std::pair<char, int>& a, const std::pair<char, int>& b) {
        return a.second > b.second;
    });

   
    std::string engFreq = "etaoinshrdlcumwfgypbvkjxqz";
    std::map<char, char> mapping;
    for (size_t i = 0; i < sortedFreq.size() && i < engFreq.length(); i++) {
        mapping[sortedFreq[i].first] = engFreq[i];
    }

    
    std::string result = "";
    for (char c : ciphertext) {
        if (!isalpha(c)) { result += c; continue; }
        char r = mapping[tolower(c)];
        result += isupper(c) ? toupper(r) : r;
    }
    std::cout << result << std::endl;
}


void cryptanalysisAffine(std::string ciphertext) {
    std::vector<int> valid_a = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
    

    std::cout << "--- Brute Force ---" << std::endl;
    std::cout << "Key (a, b) | Decrypted Text" << std::endl;
    std::cout << "------------------------------" << std::endl;

    int counter = 0;
    for (int a : valid_a) {
        for (int b = 0; b < 26; b++) {
            std::string decrypted = affineCipher(ciphertext, a, b, false);
            
            
            std::cout  << "(" 
                 << std::setw(2) << a << ", " << std::setw(2) << b << ") | " 
                 << decrypted << std::endl;
        }
    }
    
    
    
    
}

void cryptanalysisAffineRecurrent(std::string ciphertext, std::string knownPlaintextPrefix) {
    std::cout << "Affine Recurrent Known-Plaintext Attack:" << std::endl;
    std::vector<int> valid_a = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
    
    std::cout << "Searching for keys... " << std::endl;
    
    for (int a1 : valid_a) {
        for (int b1 = 0; b1 < 26; b1++) {
            for (int a2 : valid_a) {
                for (int b2 = 0; b2 < 26; b2++) {
                    
                    
                    std::string testCipher = affineRecurrent(knownPlaintextPrefix, a1, b1, a2, b2, true);
                    
                    
                    if (ciphertext.find(testCipher) == 0) {
                        std::cout << "SUCCESS! Keys found: " << std::endl;
                        std::cout << "a1 = " << a1 << ", b1 = " << b1 << std::endl;
                        std::cout << "a2 = " << a2 << ", b2 = " << b2 << std::endl;
                        
                        
                        std::string fullDecrypted = affineRecurrent(ciphertext, a1, b1, a2, b2, false);
                        std::cout << "\nDecrypted full text:\n" << fullDecrypted << std::endl;
                        return;
                    }
                }
            }
        }
    }
    
}


std::string getTestText() {
    return "the quick brown fox jumps over the lazy dog the quick brown fox jumps over the lazy dog "
    "it was the best of times it was the worst of times it was the age of wisdom it was the age of foolishness "
    "to be or not to be that is the question whether tis nobler in the mind to suffer the slings and arrows "
    "of outrageous fortune or to take arms against a sea of troubles and by opposing end them "
    "all that glitters is not gold often have you heard that told many a man his life hath sold but my outside to behold "
    "gilding the lily is foolish when the flower itself is already beautiful the course of true love never did run smooth "
    "now is the winter of our discontent made glorious summer by this sun of york and all the clouds that loured upon our house "
    "in the deep bosom of the ocean buried now are our brows bound with victorious wreaths our bruised arms hung up for monuments "
    "this above all to thine own self be true and it must follow as the night the day thou canst not then be false to any man "
    "the lady doth protest too much methinks brevity is the soul of wit and tediousness the limbs and outward flourishes "
    "i will be brief your noble son is mad for what is madness but to have too much grace and too much wisdom "
    "friends romans countrymen lend me your ears i come to bury caesar not to praise him the evil that men do lives after them "
    "the good is oft interred with their bones so let it be with caesar the noble brutus hath told you caesar was ambitious "
    "if it were so it was a grievous fault and grievously hath caesar answered it here under leave of brutus and the rest "
    "for brutus is an honourable man so are they all all honourable men come i to speak in caesars funeral "
    "he was my friend faithful and just to me but brutus says he was ambitious and brutus is an honourable man "
    "he hath brought many captives home to rome whose ransoms did the general coffers fill did this in caesar seem ambitious "
    "when that the poor have cried caesar hath wept ambition should be made of sterner stuff yet brutus says he was ambitious "
    "and brutus is an honourable man you all did see that on the lupercal i thrice presented him a kingly crown which he did thrice refuse "
    "was this ambition yet brutus says he was ambitious and sure he is an honourable man i speak not to disprove what brutus spoke "
    "but here i am to speak what i do know you all did love him once not without cause what cause withholds you then to mourn for him "
    "o judgement thou art fled to brutish beasts and men have lost their reason bear with me my heart is in the coffin there with caesar "
    "and i must pause till it come back to me theres a divinity that shapes our ends rough hew them how we will "
    "we are such stuff as dreams are made on and our little life is rounded with a sleep life is but a walking shadow a poor player "
    "that struts and frets his hour upon the stage and then is heard no more it is a tale told by an idiot full of sound and fury "
    "signifying nothing to sleep perchance to dream ay theres the rub for in that sleep of death what dreams may come "
    "when we have shuffled off this mortal coil must give us pause theres the respect that makes calamity of so long life "
    "who would fardels bear to grunt and sweat under a weary life but that the dread of something after death the undiscovered country "
    "from whose bourn no traveller returns puzzles the will and makes us rather bear those ills we have than fly to others that we know not of "
    "all the worlds a stage and all the men and women merely players they have their exits and their entrances and one man in his time plays many parts "
    "his acts being seven ages at first the infant mewling and puking in the nurses arms then the whining schoolboy with his satchel "
    "and shining morning face creeping like snail unwillingly to school then the lover sighing like furnace with a woeful ballad "
    "made to his mistress eyebrow then a soldier full of strange oaths and bearded like the pard jealous in honour sudden and quick in quarrel "
    "seeking the bubble reputation even in the cannons mouth then the justice in fair round belly with good capon lined with eyes severe "
    "and beard of formal cut full of wise saws and modern instances and so he plays his part the sixth age shifts into the lean and slippered pantaloon "
    "with spectacles on nose and pouch on side his youthful hose well saved a world too wide for his shrunk shank and his big manly voice "
    "turning again toward childish treble pipes and whistles in his sound last scene of all that ends this strange eventful history "
    "is second childishness and mere oblivion sans teeth sans eyes sans taste sans everything "
    "the first thing we do lets kill all the lawyers out damned spot out i say one two why then tis time to doot hell is murky "
    "fie my lord fie a soldier and afeard what need we fear who knows it when none can call our power to account yet who would have thought the old man to have had so much blood in him "
    "tomorrow and tomorrow and tomorrow creeps in this petty pace from day to day to the last syllable of recorded time "
    "and all our yesterdays have lighted fools the way to dusty death out out brief candle lifes but a walking shadow "
    "double double toil and trouble fire burn and cauldron bubble by the pricking of my thumbs something wicked this way comes "
    "fair is foul and foul is fair hover through the fog and filthy air something is rotten in the state of denmark "
    "there are more things in heaven and earth horatio than are dreamt of in your philosophy to be or not to be that is the question "
    "neither a borrower nor a lender be for loan oft loses both itself and friend and borrowing dulls the edge of husbandry "
    "this above all to thine own self be true and it must follow as the night the day thou canst not then be false to any man "
    "though she be but little she is fierce the better part of valor is discretion in the which it is better to have a fool for a friend "
    "the fool doth think he is wise but the wise man knows himself to be a fool we know what we are but know not what we may be "
    "hell is empty and all the devils are here the course of true love never did run smooth for aught that i could ever read "
    "could ever hear by tale or history the course of true love never did run smooth love looks not with the eyes but with the mind "
    "and therefore is winged cupid painted blind nor hath loves mind of any judgement taste wings and no eyes figure unheedy haste "
    "the lunatic the lover and the poet are of imagination all compact madness in great ones must not unwatched go "
    "how far that little candle throws his beams so shines a good deed in a naughty world some are born great some achieve greatness "
    "and some have greatness thrust upon them be not afraid of greatness some are born great some achieve greatness and some have greatness thrust upon them "
    "the evil that men do lives after them the good is oft interred with their bones cowards die many times before their deaths "
    "the valiant never taste of death but once of all the wonders that i yet have heard it seems to me most strange that men should fear "
    "seeing that death a necessary end will come when it will come it is a tale told by an idiot full of sound and fury signifying nothing "
    "life is a tale told by an idiot full of sound and fury signifying nothing brevity is the soul of wit there are more things in heaven and earth "
    "than are dreamt of in your philosophy the lady doth protest too much methinks all that glitters is not gold to be or not to be "
    "now is the winter of our discontent the better part of valor is discretion some are born great some achieve greatness "
    "though she be but little she is fierce hell is empty and all the devils are here the course of true love never did run smooth ";
}
int main() {
    std::string msg;
    
    std::cout << "Enter text to encrypt: ";
    std::getline(std::cin, msg); 

    int choice;
    std::cout << "Enter a variant of encryption: " << std::endl;
    std::cout << "1. Simple Subctitution " << std::endl;
    std::cout << "2. AffineCipher: " << std::endl;
    std::cout << "3. AffineReccurent: " << std::endl;
    std::cout << "4. CryptoAnalysis " << std::endl;

    std::cin >> choice;
    std::cout << std:: endl;
    std::cout << "\nOriginal text: " << msg << "\n\n";

    switch (choice)
    {
    case 1: {
        //std::string subKey = "qwertyuiopasdfghjklzxcvbnm"; 
        std::string subKey;
        std::cout << "Enter a secret key for ecryption(26 unique english symbols): ";
        std::cin >> subKey;
        std::cout << "Simple Substitution Cipher:" << std::endl;
        std::string subEnc = simpleSubstitution(msg, subKey, true);
        std::cout << "Encrypted: " << subEnc << std::endl;
        std::cout << "Decrypted: " << simpleSubstitution(subEnc, subKey, false) << "\n\n";
        break;
    }
    case 2: {
        int a, b;
        std::cout << "Enter secret values (a,b): ";
        std::cin >> a >> b;
        std::cout << "Affine Cipher:" << std::endl;
        std::string affEnc = affineCipher(msg, a, b, true);
        std::cout << "Encrypted: " << affEnc << std::endl;
        std::cout << "Decrypted: " << affineCipher(affEnc, a, b, false) << "\n\n";
        break;
    }
    case 3: {
        int a1, b1, a2, b2;
        std::cout << "Enter secret values (a1,b1, a2, b2): ";
        std::cin >> a1 >> b1 >> a2 >> b2;
        std::cout << "Affine Recurrent Cipher:" << std::endl;
        std::string affRecEnc = affineRecurrent(msg, a1, b1, a2, b2, true);
        std::cout << "Encrypted: " << affRecEnc << std::endl;
        std::cout << "Decrypted: " << affineRecurrent(affRecEnc, a1, b1, a2, b2, false) << std::endl;
        break;
    }
    case 4: {
          

    
    std::cout << "\n\n*** CRYPTANALYSIS TESTS ***\n";

    std::string longMsg = getTestText();
    std::string subKey = "qwertyuiopasdfghjklzxcvbnm"; 
    std::string affRecEnc1 = affineRecurrent(longMsg, 5, 8, 7, 3, true);
    std::string affEnc1 = affineCipher("hello", 15, 23, true);
    std::string encryptedSub = simpleSubstitution(longMsg, subKey, true);

    cryptanalysisSubstitution(encryptedSub);
    std::cout << "\n";
    cryptanalysisAffine(affEnc1);
    std::cout << "\n";
    cryptanalysisAffineRecurrent(affRecEnc1, "the quick brown");

        break;
    }
    default:
        break;
    }
  
    
    

    return 0;
}