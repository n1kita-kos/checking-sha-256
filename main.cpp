
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstddef>

using namespace std;

bool calculateSHA256(const string& filePath, string& hash)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        return false;
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr)
    {
        return false;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(context);
        return false;
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
    {
        if (EVP_DigestUpdate(context, buffer,
            static_cast<size_t>(file.gcount())) != 1)
        {
            EVP_MD_CTX_free(context);
            return false;
        }
    }

    if (!file.eof() || file.bad())
    {
        EVP_MD_CTX_free(context);
        return false;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    if (EVP_DigestFinal_ex(context, digest, &length) != 1)
    {
        EVP_MD_CTX_free(context);
        return false;
    }

    EVP_MD_CTX_free(context);
    stringstream result;

    for (unsigned int i = 0; i < length; i++)
    {
        result << hex << setw(2) << setfill('0')
               << static_cast<int>(digest[i]);
    }

    hash = result.str();

    return true;
}

int main()
{
    string choice;
    string filePath;
    cout << "1. Save hash" << endl;
    cout << "2. Verify file" << endl;
    cout << "Choice: ";

    getline(cin, choice);
    if (choice != "1" && choice != "2")
    {
        return 1;
    }

    cout << "File path: ";
    getline(cin, filePath);
    string hash;

    if (!calculateSHA256(filePath, hash))
    {
        return 1;
    }
    string hashPath = filePath + ".sha256";
    cout << "SHA-256: " << hash << endl;
    if (choice == "1")
    {
        ifstream chf(hashPath);
        if (chf.is_open())
        {
            return 1;
        }
        ofstream outf(hashPath);
        outf << hash << endl;
        outf.close();
        cout << "hash saved" << endl;
    }
    else
    {
        ifstream inpf(hashPath);
        if (!inpf.is_open())
        {
            return 1;
        }

        string expected;
        inpf >> expected;
        inpf.close();

        if (expected.length() != 64)
        {
            return 1;
        }

        bool valid = true;
        for (int i = 0; i < expected.length(); i++)
        {
            char c = expected[i];

            if (!((c >= '0' && c <= '9') ||
                  (c >= 'a' && c <= 'f')))
            {
                valid = false;
                break;
            }
        }
        if (!valid)
        {
            return 1;
        }

        if (hash == expected)
        {
            cout << "hash matches" << endl;
            return 0;
        }
        else
        {
            cout << "file changed" << endl;
            return 2;
        }
    }

    return 0;
}
