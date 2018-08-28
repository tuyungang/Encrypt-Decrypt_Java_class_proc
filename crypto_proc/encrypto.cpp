#include "encrypto.h"
//#include "lock.h"
//#include "ngx_3des_crypto.h"

CCRYPTO* CCRYPTO::m_pInstance = NULL;
CThreadMutex* CCRYPTO::m_lock = NULL;

static const std::string base64_chars =   
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
    "abcdefghijklmnopqrstuvwxyz"  
    "0123456789+/";  

static inline bool is_base64(unsigned char c) 
{  
    return (isalnum(c) || (c == '+') || (c == '/'));  
}

CCRYPTO::CCRYPTO()
{
    memset(g_CurrentPath, '\0', MAX_PATH);
    const char *TRIPLE_DES_KEY = "000000000000000000000000000000000000000000000000";
    Crypt_3Des = new Des(TRIPLE_DES_KEY);
}

CCRYPTO::~CCRYPTO()
{

}

CCRYPTO* CCRYPTO::GetInstance()
{
    if (m_pInstance == NULL) {
        m_lock->lock();
        if (m_pInstance == NULL) {
            m_pInstance = new CCRYPTO();
        }
        m_lock->unlock();
    }

    return m_pInstance;
}

void CCRYPTO::ListDir(string path)
{

}

void CCRYPTO::Crypt_init_context(char *dirPath, int &index)
{
    char *pRet = NULL;
    DIR *dirp = NULL;
    struct dirent *direntp = NULL;
    string childPath;
    string filePath;
    string curPath;
    childPath.clear();
    if (dirPath == NULL) {
        memset(g_CurrentPath, 0, MAX_PATH);
        pRet = getcwd(g_CurrentPath, MAX_PATH);
        if (pRet == NULL) {

        }
        childPath += g_CurrentPath;
        if ((dirp = opendir(g_CurrentPath)) == NULL) {

        }
    } else {
        childPath += dirPath;
        if ((dirp = opendir(dirPath)) == NULL) {
            cout << dirPath << endl;

        }
    }

    childPath += "/";
    while ((direntp = readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0 ||
                strcmp(direntp->d_name, "..") == 0 ||
                strcmp(direntp->d_name, "crypt_java") == 0) {
            continue;
        }
        if (direntp->d_type & DT_DIR) {
            curPath.clear();
            curPath = childPath;
            curPath += direntp->d_name;
            Crypt_init_context(const_cast<char *>(curPath.c_str()), index);

        } else if (direntp->d_type & DT_REG) {
            //if (strstr((*it).second->name, ".class") != NULL) {
                FILE_ENC_STRUCT *p = (FILE_ENC_STRUCT*)malloc(sizeof(FILE_ENC_STRUCT));
                p->type = 0;
                memset(p->name, 0, MAX_PATH);
                filePath.clear();
                filePath = childPath;
                filePath += direntp->d_name;
                strcpy(p->name, filePath.c_str());
                m_ReadyFileMap.insert(map<int, pFILE_ENC_STRUCT>::value_type(index, p));
                index++;
            //}
        }

        /*
        FILE_ENC_STRUCT *p = (FILE_ENC_STRUCT*)malloc(sizeof(FILE_ENC_STRUCT));
        p->type = 0;
        memset(p->name, 0, 128);
        strcpy(p->name, direntp->d_name);
        m_ReadyFileMap.insert(map<int, pFILE_ENC_STRUCT>::value_type(i, p));
        i++;
        */
    }
    if (direntp == NULL) {
        closedir(dirp);
    }
}

int CCRYPTO::User_command_prompt()
{
    int nRet = 0;
    int nRun = 0;
    cout << "功能：" << endl;
    cout << "1 加密" << endl;
    cout << "2 解密" << endl;
    cout << "0 退出" << endl;
    cout << "请选择数字：";
    cin >> nRet;
    if (nRet == 1) {
        cout << "请选择加密运行方式：" << endl;;
        cout << "1 手动(人工选择需要加密的文件)" << endl;
        cout << "2 自动(自动对所有.class文件加密)" << endl;
        cout << "请选择数字：";
        cin >> nRun;
        if (nRun == 1) {
            map<int, pFILE_ENC_STRUCT>::iterator it;
            cout << "请按数字选择您想要加密的文件:" << endl;
            for (it = m_ReadyFileMap.begin(); it != m_ReadyFileMap.end(); it++) {
                cout << (*it).first << " " << (*it).second->name << endl;
            }
            int cmd;
            while (1) {
                cout << "请选择数字(0是选择完毕)：";
                cin >> cmd;
                it = m_ReadyFileMap.begin();
                it = m_ReadyFileMap.find(cmd);
                if (it != m_ReadyFileMap.end()) {
                    if ((*it).second->type == 0) {
                        if (strstr((*it).second->name, ".class") != NULL) {
                            (m_ReadyFileMap[cmd])->type = 2;
                        } else {
                            (m_ReadyFileMap[cmd])->type = 1;
                        }
                    } else {
                        cout << "已选择，请重新选择！" << endl;
                        continue;
                    }
                } 
                else {
                    if (cmd != 0) {
                        cout << "请重新选择!" << endl;
                    }
                }
                if (cmd == 0) {
                    cout << "选择完毕" << endl;
                    break;
                }
            }
        } 
        else {
            map<int, pFILE_ENC_STRUCT>::iterator it;
            for (it = m_ReadyFileMap.begin(); it != m_ReadyFileMap.end(); it++) {
                if ((*it).second->type == 0) {
                    if (strstr((*it).second->name, ".class") != NULL) {
                        (m_ReadyFileMap[(*it).first])->type = 2;
                    }
                }
            }
        }
    } else if (nRet == 2) {

    }
    else {
    }

    return nRet;
}

int CCRYPTO::Crypt_recyle_res()
{
    if (m_ReadyFileMap.empty()) {
        return 0; 
    }
    map<int, pFILE_ENC_STRUCT>::iterator it;
    for (it = m_ReadyFileMap.begin(); it != m_ReadyFileMap.end(); it++) {
        free(it->second);
    }
    m_ReadyFileMap.clear();

    return 0;
}

void CCRYPTO::Encrypto_data()
{
    long nSize;
    map<int, pFILE_ENC_STRUCT>::iterator it;
    for (it = m_ReadyFileMap.begin(); it != m_ReadyFileMap.end(); it++) {
        if ((*it).second->type != 0) {
            char sTmpPath[1024] = {0};
            sprintf(sTmpPath, "%s", (*it).second->name);
            FILE *pFile = NULL;
            pFile = fopen(sTmpPath, "rb");
            fseek(pFile, 0, SEEK_END);
            nSize = 0;
            nSize = ftell(pFile); 
            rewind(pFile);
            long nFileFlag = 0;
            fread(&nFileFlag, sizeof(long), 1, pFile);
            if (ntohl(nFileFlag) == 0x1100) {
                cout << (*it).second->name << " 已加密过" << endl;
                fclose(pFile);
                continue;
            }
            rewind(pFile);

            char *pBuffer = (char*)malloc(nSize + 1);
            memset(pBuffer, 0, nSize + 1);
            string encoded;
            if ((*it).second->type == 1) {
                long nLen = 0;
                long nRSize = nSize;
                while (nLen < nSize) {
                    long nRlen = fread(pBuffer + nLen, sizeof(char), nRSize, pFile);
                    if (nRlen > 0) {
                        nRSize -= nRlen;
                        nLen += nRlen;
                    } else
                        break;
                }
                if (nLen < nSize) {
                    free(pBuffer);
                    fclose(pFile);
                    continue;
                }
                fclose(pFile);

                string src_str(pBuffer);
                //TODO:3des
                encoded = Encrypto_des(src_str);

            } else {
                char ch;  
                int i = 0;
                while (!feof(pFile)) {
                    pBuffer[i] = fgetc(pFile);
                    i++;
                }
                /*
                while(EOF != (ch=fgetc(pFile))) {  
                    pBuffer[i] = ch; 
                    i++;
                }
                */
                fclose(pFile);

                int count = i;
                i = 0;
                string src_str;
                while (i < count - 1) {
                    src_str += pBuffer[i];
                    i++;
                }

                //TODO:base64
                encoded = Encrypto_base64(reinterpret_cast<const unsigned char*>(src_str.c_str()), src_str.length());

            }

            if (encoded.empty()) {

            }
            char *enc_buf = (char*)malloc(encoded.size() + 1);
            memset(enc_buf, 0, encoded.size() + 1);
            memcpy(enc_buf, encoded.c_str(), encoded.size());

            pFile = NULL;
            pFile = fopen(sTmpPath, "wb");
            fseek(pFile, 0, SEEK_SET);
            long fileFlag = htonl(0x1100);
            fwrite(&fileFlag, sizeof(long), 1, pFile);
            long nLen = 0;
            long nWFileSize = encoded.size();
            while (nLen < encoded.size()) {
                long nWlen = fwrite(enc_buf + nLen, sizeof(char), nWFileSize, pFile);
                if (nWlen <= 0) {
                    break;
                }
                nWFileSize -= nWlen;
                nLen += nWlen;
            }
            free(enc_buf);
            free(pBuffer);
            enc_buf = NULL;
            pBuffer = NULL;
            fclose(pFile);
            cout << (*it).second->name << " 文件加密成功！" << endl;
        }
    }
}

void CCRYPTO::Decrypto_data(char *dirPath)
{
    DIR *dirp;
    char *pRet = NULL;
    struct dirent *direntp;
    string childPath, curPath;
    childPath.clear();
    if (dirPath == NULL) {
        memset(g_CurrentPath, 0, MAX_PATH);
        pRet = getcwd(g_CurrentPath, MAX_PATH);
        if (pRet == NULL) {

        }
        childPath += g_CurrentPath;
        if ((dirp = opendir(g_CurrentPath)) == NULL) {

        }
    } else {
        childPath += dirPath;
        if ((dirp = opendir(dirPath)) == NULL) {
            cout << dirPath << endl;

        }
    }

    childPath += "/";
    while ((direntp = readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0 ||
                strcmp(direntp->d_name, "..") == 0 ||
                strcmp(direntp->d_name, "crypt_java") == 0) {
            continue;
        }
        if (direntp->d_type & DT_DIR) {
            curPath.clear();
            curPath = childPath;
            curPath += direntp->d_name;
            Decrypto_data(const_cast<char *>(curPath.c_str()));

        } else if (direntp->d_type & DT_REG) {
            if (strstr(direntp->d_name, ".class") == NULL) {
                continue;
            }

            char sTmpPath[1024] = {0};
            sprintf(sTmpPath, "%s%s", childPath.c_str(), direntp->d_name);
            FILE *pFile = NULL;
            pFile = fopen(sTmpPath, "rb");
            fseek(pFile, 0, SEEK_END);
            long nFileSize = ftell(pFile);
            rewind(pFile);
            long nFileFlag = 0;
            fread(&nFileFlag, sizeof(long), 1, pFile);
            if (ntohl(nFileFlag) != 0x1100) {
                fclose(pFile);
                continue;
            }
            nFileSize = nFileSize - sizeof(long);
            char *pBuffer = (char*)malloc(nFileSize + 1);
            memset(pBuffer, 0, nFileSize + 1);
            long nLen = 0;
            long nRSize = nFileSize;
            while (nLen < nFileSize) {
                int nRlen = fread(pBuffer + nLen, sizeof(char), nRSize, pFile);
                if (nRlen > 0) {
                    nRSize -= nRlen;
                    nLen += nRlen;
                } else 
                    break;
            }
            fclose(pFile);

            string enc_str(pBuffer);
            string dec_out;
            if (strstr(direntp->d_name, ".class") == NULL) {
                //TODO:dec_3des
                dec_out = Decrypto_des(enc_str);

                char *dec_buf = (char*)malloc(dec_out.size() + 1);
                memset(dec_buf, 0, dec_out.size() + 1);
                memcpy(dec_buf, dec_out.c_str(), dec_out.size());

                pFile = NULL;
                pFile = fopen(sTmpPath, "wb");
                nLen = 0;
                long nWSize = dec_out.size();
                while (nLen < dec_out.size()) {
                    long nWlen = fwrite(dec_buf + nLen, sizeof(char), nWSize, pFile);
                    if (nWlen <= 0) {
                        break;
                    }
                    nWSize -= nWlen;
                    nLen += nWlen;
                }
                free(dec_buf);
                dec_buf = NULL;

            } else {
                //TODO:dec_base64
                dec_out = Decrypto_base64(enc_str);
                //ofstream out("out.txt");
                //out << dec_out << endl;

                char *dec_buf = (char*)malloc(dec_out.size() + 1);
                memset(dec_buf, 0, dec_out.size() + 1);
                memcpy(dec_buf, dec_out.c_str(), dec_out.size());

                pFile = NULL;
                pFile = fopen(sTmpPath, "wb");
                fseek(pFile, 0, SEEK_SET);
                nLen = 0;
                long nWSize = dec_out.size();
                while (nLen < dec_out.size()) {
                    long nWlen = fwrite(dec_buf + nLen, sizeof(char), nWSize, pFile);
                    if (nWlen <= 0) {
                        break;
                    }
                    nWSize -= nWlen;
                    nLen += nWlen;
                }
                free(dec_buf);
                dec_buf = NULL;

            }
            
            free(pBuffer);
            pBuffer = NULL;
            fclose(pFile);
            cout << sTmpPath << " 文件解密成功！" << endl;
        }
    }
    if (direntp == NULL) {
        closedir(dirp);
    }
}

string CCRYPTO::Encrypto_des(string in)
{
    return Crypt_3Des->desEncrypt(in);
}

string CCRYPTO::Decrypto_des(string in)
{
    return Crypt_3Des->desDecrypt(in);
}

string CCRYPTO::Encrypto_base64(unsigned char const* bytes_to_encode, unsigned int in_len)
{
    std::string ret;  
    int i = 0;  
    int j = 0;  
    unsigned char char_array_3[3];  
    unsigned char char_array_4[4];  

    while (in_len--) {  
        char_array_3[i++] = *(bytes_to_encode++);  
        if (i == 3) {  
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;  
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);  
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);  
            char_array_4[3] = char_array_3[2] & 0x3f;  

            for(i = 0; (i <4) ; i++)  
                ret += base64_chars[char_array_4[i]];  
            i = 0;  
        }  
    }  

    if (i)  
    {  
        for(j = i; j < 3; j++)  
            char_array_3[j] = '\0';  

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;  
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);  
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);  
        char_array_4[3] = char_array_3[2] & 0x3f;  

        for (j = 0; (j < i + 1); j++)  
            ret += base64_chars[char_array_4[j]];  

        while((i++ < 3))  
            ret += '=';  

    }  

    return ret;
}

string CCRYPTO::Decrypto_base64(string const& encoded_string)
{
    int in_len = encoded_string.size();  
    int i = 0;  
    int j = 0;  
    int in_ = 0;  
    unsigned char char_array_4[4], char_array_3[3];  
    std::string ret;  

    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {  
        char_array_4[i++] = encoded_string[in_]; in_++;  
        if (i ==4) {  
            for (i = 0; i <4; i++)  
                char_array_4[i] = base64_chars.find(char_array_4[i]);  

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);  
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);  
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];  

            for (i = 0; (i < 3); i++)  
                ret += char_array_3[i];  
            i = 0;  
        }  
    }  

    if (i) {  
        for (j = i; j <4; j++)  
            char_array_4[j] = 0;  

        for (j = 0; j <4; j++)  
            char_array_4[j] = base64_chars.find(char_array_4[j]);  

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);  
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);  
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];  

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];  
    }  

    return ret;
}

/*
bool CCRYPTO::Encrypto_java()
{
    map<int, pFILE_ENC_STRUCT>::iterator it;
    for (it = m_ReadyFileMap.begin(); it != m_ReadyFileMap.end(); it++) {
        if ((*it).second->type == 1) {
            char sTmpPath[512] = {0};
            sprintf(sTmpPath, "%s/%s", g_CurrentPath, (*it).second->name);
            FILE *pFile = NULL;
            pFile = fopen(sTmpPath, "rb");
            fseek(pFile, 0, SEEK_END);
            long nSize = 0;
            nSize = ftell(pFile); 
            rewind(pFile);
            long nFileFlag = 0;
            fread(&nFileFlag, sizeof(long), 1, pFile);
            if (ntohl(nFileFlag) == 0x1100) {
                cout << (*it).second->name << " 已加密过" << endl;
                fclose(pFile);
                continue;
            }
            rewind(pFile);
            char *pBuffer = (char*)malloc(nSize + 1);
            memset(pBuffer, 0, nSize + 1);
            long nLen = 0;
            long nRSize = nSize;
            while (nLen < nSize) {
                char szBuffer[40960] = {0};
                int nRlen = fread(szBuffer, sizeof(char), 40960, pFile);
                if (nRlen > 0) {
                    memcpy(pBuffer, szBuffer, nRlen);
                    nLen += nRlen;
                } else
                    break;
            }
            if (nLen < nSize) {
                free(pBuffer);
                fclose(pFile);
                continue;
            }
            cout << "ready enc:"<< pBuffer << endl;
            fclose(pFile);

            pFile = NULL;
            pFile = fopen(sTmpPath, "wb");
            if (pFile == NULL)
                return false;

            fseek(pFile, 0, SEEK_SET);
            long lFileType = htonl(0x1100);
            fwrite(&lFileType, sizeof(long), 1, pFile);

            unsigned char szEncodeKey[16] = {0};
            unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
            int nIndex = 0;
            for (nIndex = 0; nIndex < 16; nIndex++)
            {
                if (nIndex % 3 == 0)
                {
                    szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
                }
                else if (nIndex % 3 == 1)
                {
                    szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
                }
                else
                {
                    szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
                }
            }

            char uszEncodeData[4096] = {0};
            int nEncodeLen = 0;
            int nBufferIndex = strlen(pBuffer);
            AES_CryptDataEVP((unsigned char*)pBuffer, nBufferIndex, szEncodeKey, (unsigned char*)uszEncodeData, &nEncodeLen);

            int nDataLen = 0;
            while (nEncodeLen > 0)
            {
                int nWriteLen = fwrite(uszEncodeData + nDataLen, sizeof(char), nEncodeLen, pFile);
                if (nWriteLen <= 0)
                    break;
                nEncodeLen -= nWriteLen;
                nDataLen += nWriteLen;
            }

            fclose(pFile);
        }
    }
    return true;
}

bool CCRYPTO::Decrypto_java()
{
    DIR *dirp;
    struct dirent *direntp;
    if ((dirp = opendir(g_CurrentPath)) == NULL) {

    }
    while ((direntp = readdir(dirp)) != NULL) {
        if (strcmp(direntp->d_name, ".") == 0 ||
                strcmp(direntp->d_name, "..") == 0 ||
                strcmp(direntp->d_name, "crypt_java") == 0) {
            continue;
        }
        char sTmpPath[512] = {0};
        sprintf(sTmpPath, "%s/%s", g_CurrentPath, direntp->d_name);
        FILE *pFile = NULL;
        pFile = fopen(sTmpPath, "rb");
        fseek(pFile, 0, SEEK_END);
        long nFileSize = ftell(pFile);
        if (nFileSize == 0) {
            fclose(pFile);
            continue;
        }
        rewind(pFile);

        long nFileFlag = 0;
        fread(&nFileFlag, sizeof(long), 1, pFile);
        if (ntohl(nFileFlag) != 0x1100) {
            fclose(pFile);
            continue;
        }
        nFileSize -= sizeof(long);
        char *pBuffer = (char*)malloc(nFileSize + 1);
        memset(pBuffer, 0, nFileSize + 1);

        long nLen = 0;
        while (nLen < nFileSize) {
            char szBuffer[40960] = {0};
            int nRlen = fread(szBuffer, sizeof(char), 40960, pFile);
            if (nRlen > 0) {
                memcpy(pBuffer, szBuffer, nRlen);
                nLen += nRlen;
            } else 
                break;
        }
        fclose(pFile);
        if (nLen < nFileSize) {
            free(pBuffer);
            continue;
        }

        char* pszDecodeData = (char*)malloc(nFileSize * 2);
        if (pszDecodeData == NULL) {
            free(pBuffer);
            return false;
        }
        memset(pszDecodeData, 0, nFileSize * 2);
        
        unsigned char szEncodeKey[16] = {0};
        unsigned char szEndData[16] = { 0xe1, 0x02, 0xa3, 0x04, 0x15, 0xb6, 0x07, 0x08, 0xc9, 0x0a, 0xab, 0x0c, 0x6d, 0x0e, 0x2f, 0x01 };
        int nIndex = 0;
        for (nIndex = 0; nIndex < 16; nIndex++)
        {
            if (nIndex % 3 == 0)
            {
            szEncodeKey[nIndex] = (0x0f) & (szEndData[nIndex] >> 2);
            }
            else if (nIndex % 3 == 1)
            {
            szEncodeKey[nIndex] = (0x1f) & (szEndData[nIndex] >> 3);
            }
            else
            {
            szEncodeKey[nIndex] = (0x3f) & (szEndData[nIndex] >> 4);
            }
        }
        int nDecodeLen = 0;
        int nEncodeLen = 0;
        AES_DecryptDataEVP((unsigned char*)pBuffer, nFileSize, szEncodeKey, (unsigned char*)pszDecodeData, &nDecodeLen);
        if (nDecodeLen == 0)
        {
            free(pBuffer);
            free(pszDecodeData);
            return false;
        }
        free(pBuffer);

        pFile = NULL;
        pFile = fopen(sTmpPath, "wb");
        if (pFile == NULL)
            return false;

        fseek(pFile, 0, SEEK_SET);
        int nDataLen = 0;
        while (nEncodeLen > 0) {
            int nWriteLen = fwrite(pszDecodeData + nDataLen, sizeof(char), nDecodeLen, pFile);
            if (nWriteLen <= 0)
                break;
            nEncodeLen -= nWriteLen;
            nDataLen += nWriteLen;
        }
        fclose(pFile);
        free(pszDecodeData);
    }
    if (direntp == NULL) {
        closedir(dirp);
    }
    return true;
}

void CCRYPTO::Encrypto_3des(char *in, long size, char *out, int *out_len)
{
    int i = 0;
    int len = 0;
    int nlen = 0;
    int klen = 0;
    char ch = '\0';

    const char *u_key = "ABCDEFGHIJKLMNOPQRSTUVWX";

    unsigned char key[LEN_OF_KEY];
    unsigned char tmp[1024] = {0};
    unsigned char src[1024] = {0};

    unsigned char block[8] = {0};
    DES_key_schedule ks1, ks2, ks3;

    klen = strlen(u_key);
    memcpy(key, u_key, klen);
    memset(key + klen, 0x00, LEN_OF_KEY - klen); 


    memcpy(block, key, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks1);

    memcpy(block, key + 8, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks2);

    memcpy(block, key + 16, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks3);

    //nlen = size;
    nlen = strlen(in);
    memcpy(src, in, nlen);

    len = (nlen / 8 + 1) * 8;

    ch = 8 - nlen % 8;
    memset(src + nlen, ch, (8 - nlen % 8));

    for (i = 0; i < len; i += 8) {
        DES_ecb3_encrypt((const_DES_cblock *)(src + i), (DES_cblock *)(out + i), &ks1, &ks2, &ks3, DES_ENCRYPT);
    }
    *out_len = len;

}

void CCRYPTO::Decrypto_3des(char *in, int size, char *out)
{
    int i = 0;
    int len = 0;
    int nlen = 0;
    int klen = 0;
    char ch = '\0';

    const char *u_key = "ABCDEFGHIJKLMNOPQRSTUVWX";

    unsigned char key[LEN_OF_KEY];
    unsigned char tmp[1024] = {0};
    unsigned char src[1024] = {0};

    unsigned char block[8] = {0};
    DES_key_schedule ks1, ks2, ks3;

    klen = strlen(u_key);
    memcpy(key, u_key, klen);
    memset(key + klen, 0x00, LEN_OF_KEY - klen); 


    memcpy(block, key, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks1);

    memcpy(block, key + 8, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks2);

    memcpy(block, key + 16, sizeof(block));
    TDES_set_key_unchecked((const_DES_cblock *)block, &ks3);

    //nlen = size;
    //nlen = strlen(in);
    //memcpy(src, in, nlen);

    //len = (nlen / 8 + 1) * 8;
    len = size;

    //ch = 8 - nlen % 8;
    //memset(src + nlen, ch, (8 - nlen % 8));

    for (i = 0; i < 1000; i += 8) {
        DES_ecb3_encrypt((const_DES_cblock *)(in + i), (DES_cblock *)(out + i), &ks1, &ks2, &ks3, DES_DECRYPT);
    }

    for (i = 0; i < 1000; i++) {
        printf("%c", *(out + i));
    }
    printf("\n");
}



void CCRYPTO::Encrypto_aes(char *in, long size, char *out, unsigned int *out_len)
{
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        
    unsigned char iv[AES_BLOCK_SIZE];        
    unsigned char* input_string;
    unsigned char* encrypt_string;
    //unsigned char* decrypt_string;
    unsigned int len;        
    unsigned int i;

    len = 0;
    if ((strlen(in) + 1) % AES_BLOCK_SIZE == 0) {
        len = strlen(in) + 1;
    } else {
        len = ((strlen(in) + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    }


    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, in, strlen(in));

    memcpy(key, "192.168.2.155###", strlen("192.168.2.155###"));


    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_encrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set encryption key in AES\n");
        exit(-1);
    }

    encrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));    
    if (encrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for encrypt_string\n");
        exit(-1);
    }

    AES_cbc_encrypt(input_string, encrypt_string, len, &aes, iv, AES_ENCRYPT);
    memcpy(out, encrypt_string, len);
    *out_len = len;

}

void CCRYPTO::Decrypto_aes(char *in, unsigned int size, char *out)
{
    AES_KEY aes;
    unsigned char key[AES_BLOCK_SIZE];        
    unsigned char iv[AES_BLOCK_SIZE];        
    unsigned char* input_string;
    //unsigned char* encrypt_string;
    unsigned char* decrypt_string;
    unsigned int len;
    unsigned int i;

    len = size;

    memcpy(key, "192.168.2.155###", strlen("192.168.2.155###"));

    input_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (input_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for input_string\n");
        exit(-1);
    }
    strncpy((char*)input_string, in, len);

    decrypt_string = (unsigned char*)calloc(len, sizeof(unsigned char));
    if (decrypt_string == NULL) {
        fprintf(stderr, "Unable to allocate memory for decrypt_string\n");
        exit(-1);
    }


    for (i=0; i<AES_BLOCK_SIZE; ++i) {
        iv[i] = 0;
    }
    if (AES_set_decrypt_key(key, 128, &aes) < 0) {
        fprintf(stderr, "Unable to set decryption key in AES\n");
        exit(-1);
    }

    AES_cbc_encrypt(input_string, decrypt_string, len, &aes, iv, AES_DECRYPT);
    //AES_cbc_encrypt((unsigned char*)in, decrypt_string, len, &aes, iv, AES_DECRYPT);
    memcpy(out, decrypt_string, strlen((char*)decrypt_string));

}
*/
