#include <jni.h>
#include <jvmti.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

jvmtiEnv* m_pJvmTI = NULL;


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

	printf("class name=%s len=%d,\n", name,class_data_len);


	 unsigned char** b1;

	 jint len=0,i=0,k=0;
	 len=class_data_len%2==0?class_data_len/2:class_data_len/2+1;

     jvmti_env->Allocate(class_data_len, new_class_data);
     jvmti_env->Allocat(b1,len);
     jvmti_env->Allocat(buf,class_data_len);
     memcpy(*b1,class_data,len);

	  for(i=0;i<class_data_len;i+=2){
		  new_class_data[]
	  }

	/**
	 * 數據奇數和偶數的解密
	 *
	 * @param mystr
	 * @return
	
	private byte[] dcode(byte[] mystr) {
		byte[] b1 = new byte[mystr.length % 2 == 0 ? mystr.length / 2 : mystr.length / 2 + 1];// 單數
		System.arraycopy(mystr, 0, b1, 0, b1.length);
		byte[] buf = new byte[mystr.length];
		int k = 0;
		for (int i = 0; i < mystr.length; i += 2) {
			buf[i] = b1[k];
			if (i + 1 < mystr.length) {
				buf[i + 1] = mystr[b1.length + k];
			}
			k += 1;
		} */

		return buf;
	}


	//执行解密
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
