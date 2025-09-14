#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <cstdlib>
using namespace std;

// Generate a fake unique ID (random hex string)
string generateID() {
    string hex = "0123456789ABCDEF";
    string id = "";
    for (int i = 0; i < 8; i++) {
        id += hex[rand() % 16];
    }
    return id;
}

// Simple "encryption" = XOR with key (demo only)
string encryptMessage(const string &msg, int key) {
    string enc = msg;
    for (size_t i = 0; i < enc.size(); i++) {
        enc[i] = enc[i] ^ key; // XOR with key
    }
    return enc;
}

// Decryption (same as encryption here)
string decryptMessage(const string &enc, int key) {
    return encryptMessage(enc, key); // XOR again = original
}

int main() {
    srand(time(0));

    // Register users with unique IDs
    map<string, string> registry;
    string aliceID = generateID();
    registry[aliceID] = "Alice";

    string bobID;
    do {
        bobID = generateID();
    } while (registry.count(bobID)); // ensure unique
    registry[bobID] = "Bob";

    cout << "Registered Users:\n";
    for (map<string, string>::iterator it = registry.begin(); it != registry.end(); ++it) {
        cout << "ID: " << it->first << " -> " << it->second << "\n";
    }

    cout << "\n=== Secure Communication Demo ===\n";
    string message = "Attack at 5 AM";
    int secretKey = 123; // simple demo key

    cout << "Original Message: " << message << "\n";

    // Encrypt
    string cipher = encryptMessage(message, secretKey);
    cout << "Encrypted Message (XOR cipher): " << cipher << "\n";

    // Transmit
    cout << "Transmitting...\n";

    // Decrypt
    string plain = decryptMessage(cipher, secretKey);
    cout << "Decrypted Message: " << plain << "\n";

    // Verification
    if (plain == message) {
        cout << "Message delivered securely ✅\n";
    } else {
        cout << "Message tampered ❌\n";
    }

    return 0;
}
