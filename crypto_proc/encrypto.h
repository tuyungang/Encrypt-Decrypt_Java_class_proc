#ifndef _TU_CRYPTO_H 
#define _TU_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h> 
#include <vector>
#include <list>
#include <map>
#include <algorithm>
#include <fcntl.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "lock.h"
#include "mydes.h"

//#include "openssl/aes.h"

#define MAX_PATH 1024
//#define MAX_FILE_NAME 128

using namespace std;

typedef struct
{
    char name[MAX_PATH];
    int type;
}FILE_ENC_STRUCT, *pFILE_ENC_STRUCT;

//class CThreadMutex;
class CCRYPTO
{
    private:
        CCRYPTO();

    public:
        ~CCRYPTO();
        class freeInstance
        {
            public:
                ~freeInstance()
                {
                    if (NULL != CCRYPTO::m_pInstance) {
                        delete CCRYPTO::m_pInstance;
                    }
                }
        };
        static freeInstance _free;
    private:
        static CCRYPTO *m_pInstance;
        
        static CThreadMutex *m_lock;
        CThreadMutex m_ReadyFileMaplock;

        char g_CurrentPath[MAX_PATH];

        map<int, pFILE_ENC_STRUCT> m_ReadyFileMap;

        Des *Crypt_3Des;

    private:
        //void Encrypto_3des(char *in, long size, char *out, int *out_len);
        //void Decrypto_3des(char *in, int size, char *out);
        //void Encrypto_aes(char *in, long size, char *out, unsigned int *out_len);
        //void Decrypto_aes(char *in, unsigned int size, char *out);
        string Encrypto_des(string in);
        string Decrypto_des(string in);
        string Decrypto_base64(string const& encoded_string);
        string Encrypto_base64(unsigned char const* bytes_to_encode, unsigned int in_len);
        void ListDir(string path);

    public:
        static CCRYPTO* GetInstance();
        void Crypt_init_context(char *dirPath, int &index);
        int User_command_prompt();
        //bool Encrypto_java();
        //bool Decrypto_java();
        void Encrypto_data();
        void Decrypto_data(char *dirPath);
        int Crypt_recyle_res();
};

#endif
