#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include "encrypto.h"

using namespace std;

int main()
{
    CCRYPTO *enc = CCRYPTO::GetInstance();
    //初始化
    int index = 1;
    enc->Crypt_init_context(NULL, index);
    //用户交互
    int ret = enc->User_command_prompt();
    switch (ret) 
    {
        case 1:
            cout << "************************************************" << endl;
            cout << "**                  加密                      **" << endl;
            cout << "************************************************" << endl;
            //加密
            enc->Encrypto_data();
            break;
        case 2:
            cout << "************************************************" << endl;
            cout << "**                  解密                      **" << endl;
            cout << "************************************************" << endl;
            //解密
            enc->Decrypto_data(NULL);
            break;
        default:
            cout << "退出!" << endl;
            break;
    }
    //回收资源
    enc->Crypt_recyle_res();

    return 0;
}
