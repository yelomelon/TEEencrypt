/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEENCRYPT_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	int file;
	int cipherkey = 0;
	int* keybuf = &cipherkey;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	op.params[1].tmpref.buffer = keybuf;
	op.params[1].tmpref.size = sizeof(keybuf);

/////////////////
	if(strcmp(argv[1], "-e") == 0) { // encryption

		printf("========================Encryption========================\n");
//		printf("Please Input Plaintext : ");
//		scanf("%[^\n]s",plaintext);
		
		// read plaintext file
//		file = open("/root/plaintext.txt", O_RDONLY);
		file = open(argv[2], O_RDONLY);
		read(file, plaintext, len);
		close(file);

		if(!strcmp(plaintext, "")) strcpy(plaintext, "no file\n");
		printf("PlainText : %s", plaintext);

		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		memcpy(op.params[1].tmpref.buffer, keybuf, sizeof(keybuf));

		res = TEEC_InvokeCommand(&sess, TA_TEEENCRYPT_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		memcpy(keybuf, op.params[1].tmpref.buffer, sizeof(keybuf));

		printf("Ciphertext : %s", ciphertext);
		printf("Cipherkey : %d\n", cipherkey);

		// write ciphertext, cipherkey file
		file = open("/root/ciphertext.txt", O_CREAT|O_RDWR);	
		write(file, ciphertext, len);
		close(file);

		file = open("/root/cipherkey.txt", O_CREAT|O_RDWR);	
		write(file, &cipherkey, 1);
		close(file);

	}

	else if(strcmp(argv[1], "-d") == 0) { // decryption

		printf("========================Decryption========================\n");
//		printf("Please Input Ciphertext : ");
//		getchar();
//		scanf("%[^\n]s",ciphertext);

		// read ciphertext
		file = open(argv[2], O_RDONLY);
		read(file, ciphertext, len);
		close(file);

		// read cipherkey
		file = open(argv[3], O_RDONLY);
		read(file, keybuf, 1);
		close(file);

		printf("Ciphertext : %s", ciphertext);

		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		memcpy(op.params[1].tmpref.buffer, keybuf, sizeof(keybuf));

		res = TEEC_InvokeCommand(&sess, TA_TEEENCRYPT_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(plaintext, op.params[0].tmpref.buffer, len);

		printf("Plaintext : %s", plaintext);

		file = open("/root/plaintext.txt", O_CREAT|O_RDWR);	
		write(file, plaintext, len);
		close(file);
	}

	else {
		printf("no option");
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
