#include <jni.h>
#include <jvmti.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

jvmtiEnv* m_pJvmTI = NULL;

static const std::string base64_chars =   
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  
    "abcdefghijklmnopqrstuvwxyz"  
    "0123456789+/";  

static inline bool is_base64(unsigned char c) 
{  
    return (isalnum(c) || (c == '+') || (c == '/'));  
}

std::string Decrypto_base64(std::string const& encoded_string)
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

/**
 * 加载函数回调
 */
void JNICALL cbClassFileLoadHook(jvmtiEnv *jvmti_env,
		JNIEnv *jni_env,
		jclass class_being_redefined,
		jobject loader,
		const char *name,
		jobject protection_domain,
		jint class_data_len,
		const unsigned char* class_data,
		jint *new_class_data_len,
		unsigned char** new_class_data) {

    printf("class name=%s, len=%d\n", name, class_data_len);
    /*
    long nFileFlag = 0;
    memcpy(&nFileFlag, class_data, sizeof(long));
    if (ntohl(nFileFlag) == 0x1100) {
        char *enc_buf = (char*)malloc(class_data_len - sizeof(long) + 1);
        memset(enc_buf, 0, class_data_len - sizeof(long) + 1);
        memcpy(enc_buf, class_data + sizeof(long), class_data_len - sizeof(long));
        string enc_in(enc_buf);
        //TODO:decrypto
        string dec_out = Decrypto_base64(enc_in);
        free(enc_buf);
        enc_buf = NULL;

        *new_class_data_len = (jint)dec_out.size();
        jvmti_env->Allocate(*new_class_data_len, new_class_data);
        unsigned char *tmp_buf = *new_class_data;
        memcpy(tmp_buf, dec_out.c_str(), *new_class_data_len);
    }
    */
}

/**
 * java类加载
 */
JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
	jvmtiEnv *jvmti;
	jvmtiError error;
	// Create the JVM TI environment (jvmti).
	jint result = vm->GetEnv((void **) &jvmti, JVMTI_VERSION_1_1);
	if (result != JNI_OK) {
		printf("ERROR: Unable to access JVMTI!\n");
		return 1;
	}
	m_pJvmTI = jvmti;
	jvmtiCapabilities capabilities;
	// Clear the capabilities structure and set the ones you need.
	(void) memset(&capabilities, 0, sizeof(capabilities));

	capabilities.can_generate_all_class_hook_events = 1;
	capabilities.can_tag_objects = 1;
	capabilities.can_generate_object_free_events = 1;
	capabilities.can_get_source_file_name = 1;
	capabilities.can_get_line_numbers = 1;
	capabilities.can_generate_vm_object_alloc_events = 1;
	// Request these capabilities for this JVM TI environment.
	error = jvmti->AddCapabilities(&capabilities);
	if (error != JVMTI_ERROR_NONE) {
		printf("ERROR: Unable to AddCapabilities JVMTI!\n");
		return error;
	}

	//定义要监听的模块，这里定义了监听JVM初始化完毕模块
	jvmtiEventCallbacks callbacks;
	// Clear the callbacks structure and set the ones you want.
	(void) memset(&callbacks, 0, sizeof(callbacks));
	callbacks.ClassFileLoadHook = &cbClassFileLoadHook;
	error = jvmti->SetEventCallbacks(&callbacks, (jint) sizeof(callbacks));
	if (error != JVMTI_ERROR_NONE) {
		printf("ERROR: Unable to SetEventCallbacks JVMTI!\n");
		return error;
	}
	// For each of the above callbacks, enable this event.
	error = jvmti->SetEventNotificationMode(JVMTI_ENABLE,
			JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, (jthread) NULL);
	if (error != JVMTI_ERROR_NONE) {
		printf("ERROR: Unable to SetEventNotificationMode JVMTI!\n");
		return error;
	}
	return JNI_OK; // Indicates to the VM that the agent loaded OK.

}
