/* aes128-cts-pkcs11.c -- Generate AES128-CTS test vectors via PKCS #11
 *
 * RFC 3962 defines AES Encryption for Kerberos5, in CBC-CTS mode.
 * Appendix B lists test vectors for this encryption mode.  This program
 * generates those test vectors based on PKCS #11, to demonstrate that
 * PKCS #11 can be used as a container for this type of encryption key.
 *
 * The program hard-codes the following from RFC 3962:
 *  - AES-128 keys
 *  - The zero IV
 *  - Input
 * from this, it produces
 *  - Output
 *  - Next IV
 * in a textual form that matches the respective appendix text.
 *
 * More information can be found on
 * https://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <pkcs11.h>


#define ckr(call) { CK_RV rv = (call); if (rv != CKR_OK) { fprintf (stderr, "PKCS #11 error in %s:%d: 0x%08x\n", __FILE__, __LINE__, rv); exit (1); } }


/* Fixed data employed for all the test vectors */
int aes128key_len = 16;
uint8_t aes128key [16] = {
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
};
int iv_len = 16;
uint8_t iv [16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Each test is described in the following structure, and instantiated below.
 */
#define BUFLEN 256
struct testvec {
	uint8_t input [BUFLEN];
	uint8_t output [BUFLEN];
	uint8_t repro [BUFLEN];
	int input_len;
	int output_len;
	int repro_len;
	int nextiv_ofs;
};

#define NUMTESTS 6
struct testvec tests [NUMTESTS] = {
	{
		.output_len = 0,
		.repro_len = 0,
		.input_len = 17,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20
		},
		.nextiv_ofs = 0,
	}, {
		.output_len = 0,
		.repro_len = 0,
		.input_len = 31,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20
		},
		.nextiv_ofs = 0,
	}, {
		.output_len = 0,
		.repro_len = 0,
		.input_len = 32,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43
		},
		.nextiv_ofs = 0,
	}, {
		.output_len = 0,
		.repro_len = 0,
		.input_len = 47,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c
		},
		.nextiv_ofs = 16,
	}, {
		.output_len = 0,
		.repro_len = 0,
		.input_len = 48,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20
		},
		.nextiv_ofs = 16,
	}, {
		.output_len = 0,
		.repro_len = 0,
		.input_len = 64,
		.input = {
			0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
			0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
			0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
			0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
			0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
			0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74,
			0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e
		},
		.nextiv_ofs = 32,
	}
};


/* Encryption and decryption based on PKCS #11 key
 */
void encrypt_cbc (CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE key,
						uint8_t *data, int size) {
	uint8_t buf [BUFLEN];
	CK_MECHANISM ckm = { CKM_AES_CBC, iv, iv_len };
	CK_ULONG encrsize;
	assert (size > 0);
	assert (size < BUFLEN);
	assert (size % 16 == 0);
	ckr (C_EncryptInit (ses, &ckm, key));
	encrsize = size;
	ckr (C_Encrypt (ses, data, size, buf, &encrsize));
	assert (encrsize == size);
	memcpy (data, buf, size);
}

void decrypt_cbc (CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE key,
						uint8_t *data, int size) {
	uint8_t buf [BUFLEN];
	CK_MECHANISM ckm = { CKM_AES_CBC, iv, iv_len };
	CK_ULONG decrsize;
	assert (size > 0);
	assert (size < BUFLEN);
	assert (size % 16 == 0);
	ckr (C_DecryptInit (ses, &ckm, key));
	decrsize = size;
	ckr (C_Decrypt (ses, data, size, buf, &decrsize));
	assert (decrsize == size);
	memcpy (data, buf, size);
}


/* Iterate over all tests, and print the result in the same format as
 * in Appendix B of RFC 3962.
 */
void print_vector (char *hdr, uint8_t *data, int size) {
	int ofs = 0;
	printf ("   %s:\n", hdr);
	while (ofs < size) {
		printf ("     %04x: ", ofs);
		do {
			printf (" %02x", data [ofs++]);
		} while ((ofs < size) && ((ofs & 0x0f) != 0));
		printf ("\n");
	}
}

void print_test (struct testvec *tv) {
	printf ("\n");
	print_vector ("IV", iv, iv_len);
	print_vector ("Input", tv->repro, tv->repro_len);
	print_vector ("Output", tv->output, tv->output_len);
	print_vector ("Next IV", tv->output + tv->nextiv_ofs, iv_len);
}

void run_test (CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE key,
					struct testvec *tv) {
	uint8_t ctsencr [BUFLEN];
	uint8_t ctsdecr [BUFLEN];
	int inlenmod, cbclen, simplen, outlenmod;
	int z;
	assert (tv->input_len > 16);
	assert (tv->input_len <= BUFLEN);
	//
	// Setup 0xEE in ctsencr and 0xDD in ctsdecr; should never pop up
	memset (ctsencr, 0xEE, sizeof (ctsencr));
	memset (ctsdecr, 0xDD, sizeof (ctsdecr));
	//
	// Fetch input, encrypt and store in output
	inlenmod = tv->input_len % 16;
	memcpy (ctsencr, tv->input, tv->input_len);
	if (inlenmod > 0) {
		cbclen = tv->input_len + 16 - inlenmod;
		bzero (&ctsencr [tv->input_len], cbclen - tv->input_len);
	} else {
		cbclen = tv->input_len;
	}
	assert (cbclen >= 32);
	encrypt_cbc (ses, key, ctsencr, cbclen);
	simplen = cbclen - 32;
	memcpy (tv->output, ctsencr, simplen);
	memcpy (tv->output + simplen, ctsencr + simplen + 16, 16);
	memcpy (tv->output + simplen + 16, ctsencr + simplen, inlenmod? inlenmod: 16);
	tv->output_len = tv->input_len;
	//
	// Fetch output, decrypt and replace input
	outlenmod = tv->output_len % 16;
	if (outlenmod == 0) {
		simplen = tv->output_len - 32;
	} else {
		simplen = tv->output_len - 16 - outlenmod;
	}
	memcpy (ctsdecr + simplen + 16, tv->output + simplen, 16);
	decrypt_cbc (ses, key, ctsdecr + simplen + 16, 16);
	memcpy (ctsdecr, tv->output, simplen);
	memcpy (ctsdecr + simplen, ctsdecr + simplen + 16, 16);
	memcpy (ctsdecr + simplen, tv->output + simplen + 16, outlenmod? outlenmod: 16);
	memcpy (ctsdecr + simplen + 16, tv->output + simplen, 16);
	decrypt_cbc (ses, key, ctsdecr, simplen + 32);
	for (z = tv->output_len; z < tv->output_len + (outlenmod? (16-outlenmod): 0); z++) {
		if (ctsdecr [z] != 0x00) {
			printf ("Error: Found 0x%02x in position %d, should be 0x00\n", ctsdecr [z], z);
		}
	}
	memcpy (tv->repro, ctsdecr, tv->output_len);
	tv->repro_len = tv->output_len;
}

void run_all_tests (CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE key) {
	int t;
	printf ("\n");
	print_vector ("AES 128-bit key", aes128key, aes128key_len);
	for (t=0; t < NUMTESTS; t++) {
		run_test (ses, key, &tests [t]);
		print_test (&tests [t]);
	}
	printf ("\n");
}


/* PKCS #11 setup and key creation
 */
void setup_pkcs11_and_key (CK_SESSION_HANDLE *sesp, CK_OBJECT_HANDLE *keyp) {
	CK_SLOT_ID slots [100];
	CK_ULONG num_slots = 100;
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_OBJECT_CLASS symkobjtp = CKO_SECRET_KEY;
	CK_KEY_TYPE aeskeytp = CKK_AES;
	CK_UTF8CHAR rfc3962[] = "RFC3962";
	CK_BYTE_PTR pin;
	CK_ATTRIBUTE tmpl [] = {
		{ CKA_CLASS, &symkobjtp, sizeof (symkobjtp) },
		{ CKA_KEY_TYPE, &aeskeytp, sizeof (aeskeytp) },
		{ CKA_TOKEN, &false, sizeof (false) },
		{ CKA_LABEL, rfc3962, sizeof (rfc3962) -1 },
		{ CKA_ENCRYPT, &true, sizeof (true) },
		{ CKA_DECRYPT, &true, sizeof (true) },
		{ CKA_VALUE, aes128key, aes128key_len },
	};
	ckr (C_Initialize (NULL_PTR));
	ckr (C_GetSlotList (CK_TRUE, slots, &num_slots));
	if (num_slots < 1) {
		fprintf (stderr, "Failed to find the first token\n");
		exit (1);
	}
	ckr (C_OpenSession (slots [0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, sesp));
	pin = getpass ("Token PIN: ");
	if ((!pin) || (!*pin)) {
		printf ("Bailing out without login attempt\n");
		exit (0);
	}
	ckr (C_Login (*sesp, CKU_USER, pin, strlen (pin)));
	bzero (pin, strlen (pin));
	ckr (C_CreateObject (*sesp, tmpl, 7, keyp));
}

void cleanup_pkcs11_and_key (CK_SESSION_HANDLE ses, CK_OBJECT_HANDLE key) {
	ckr (C_DestroyObject (ses, key));
	ckr (C_CloseSession (ses));
	ckr (C_Finalize (NULL_PTR));
}


/* Main program
 */
int main (int argc, char *argv []) {
	CK_SESSION_HANDLE ses;
	CK_OBJECT_HANDLE key;
	if (argc > 1) {
		fprintf (stderr, "No arguments expected.\n");
		exit (1);
	}
	setup_pkcs11_and_key (&ses, &key);
	run_all_tests (ses, key);
	cleanup_pkcs11_and_key (ses, key);
}

