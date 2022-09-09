#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "defines.h"
#include "sshbuf.h"
#include "cipher-chachapoly-forks.h"

void discard() {
	char * linebuf;
	size_t size = 1;
	linebuf = malloc(size * sizeof(char));
	getline(&linebuf,&size,stdin);
	free(linebuf);
}

int readInt(u_int * result, u_char textmode) {
	if(!textmode) {
		if(fread(result,sizeof(u_int),1,stdin) != 1)
			return -1;
		return 0;
	} else {
		char * linebuf = NULL;
		size_t size;
		if(getline(&linebuf,&size,stdin) != -1) {
			if(sscanf(linebuf,"%u",result) == 1) {
				free(linebuf);
				return 0;
			} else {
				free(linebuf);
				return -1;
			}
		} else if (errno != ENOMEM) {
			free(linebuf);
			return -1;
		} else {
			return -1;
		}
	}
}

int readChar(u_char * result, u_char textmode) {
	if(fread(result,sizeof(u_char),1,stdin) != 1)
		return -1;
	if(textmode)
		discard();
	return 0;
}

int readBytes(u_char * result, size_t size, u_char textmode) {
	if(!textmode) {
		if(fread(result,sizeof(u_char),size,stdin) != size)
			return -1;
	} else {
		char * linebuf = NULL;
		size_t linesize;
		ssize_t r = getline(&linebuf,&size,stdin);
		if(r == 2*size + 1) {
			for(char * cursor = linebuf; *cursor == '\0'; cursor++)
				*cursor=toupper(*cursor);
			for(int i=0; i<size; i++) {
				if(sscanf(linebuf + 2*i, "%hhX", &(result[i]))
				    != 1) {
					free(linebuf);
					return -1;
				}
			}
			return 0;
		} else if (r == -1 && errno == ENOMEM) {
			return -1;
		} else {
			free(linebuf);
			return -1;
		}
	}
}

int
main(int argc, char ** argv) {
	u_char zeros[KEYSTREAMLEN + AADLEN];
	EVP_CIPHER_CTX * main_evp;
	EVP_CIPHER_CTX * header_evp;
	u_char seqbuf[16];
	u_int seqnr;

	u_char poly_key[POLY1305_KEYLEN];
	u_char headerkey[CHACHA_KEYLEN];
	u_char mainkey[CHACHA_KEYLEN];
	u_char xorStream[KEYSTREAMLEN + AADLEN];

	u_char textmode;

	u_int streams;

	u_char cmd;
	u_int param;

	u_char quitting;

	memset(zeros,0,sizeof(zeros));
	main_evp = NULL;
	header_evp = NULL;

	if(fread(&textmode, sizeof(textmode), 1, stdin) != 1)
		goto cleanup;
	if(textmode == 'b' || textmode == 'B') {
		textmode = 0;
	} else if (textmode == 't' || textmode == 'T') {
		textmode = 1;
		discard();
	} else {
		goto cleanup;
	}

	if(readInt(&streams, textmode))
		goto cleanup;
	if(readInt(&seqnr, textmode))
		goto cleanup;

	if((main_evp = EVP_CIPHER_CTX_new()) == NULL )
		goto cleanup;
	if((header_evp = EVP_CIPHER_CTX_new()) == NULL )
		goto cleanup;

	if(readBytes(mainkey, CHACHA_KEYLEN, textmode))
		goto cleanup;
	if(!EVP_CipherInit(main_evp, EVP_chacha20(), mainkey, NULL, 1))
		goto cleanup;
	explicit_bzero(mainkey, sizeof(mainkey));

	if(readBytes(headerkey, CHACHA_KEYLEN, textmode))
		goto cleanup;
	if(!EVP_CipherInit(header_evp, EVP_chacha20(), headerkey, NULL, 1))
		goto cleanup;
	explicit_bzero(headerkey, sizeof(headerkey));

	if(EVP_CIPHER_CTX_iv_length(header_evp) != 16)
		goto cleanup;
	
	quitting = 0;

	while(!readChar(&cmd,textmode)) {
		switch(cmd) {
			case 'q' :
				/* quit */
				quitting = 1;
				break;
			case 'n' :
				/* increment seqnr */
				seqnr += streams;
				break;
			case 's' :
				if(readInt(&param, textmode)) {
					quitting = 1;
					break;
				}
				seqnr = param;
				break;
			case 'g' :
				/* genererate keystream */
				memset(seqbuf,0,sizeof(seqbuf));
				POKE_U64(seqbuf+8,seqnr);
				memset(poly_key,0,sizeof(poly_key));
				if(!EVP_CipherInit(main_evp, NULL, NULL, seqbuf,
				    1)) {
					quitting=1;
					break;
				}
				if(EVP_Cipher(main_evp, poly_key, poly_key,
				    sizeof(poly_key)) < 0) {
					quitting=1;
					break;
				}
				if(!EVP_CipherInit(header_evp, NULL, NULL,
				    seqbuf, 1)) {
					quitting=1;
					break;
				}
				if(EVP_Cipher(header_evp, xorStream, zeros,
				    CHACHA_BLOCKLEN) < 0 ) {
					quitting=1;
					break;
				}
				seqbuf[0] = 1;
				if(!EVP_CipherInit(main_evp, NULL, NULL, seqbuf,
				    1)) {
					quitting=1;
					break;
				}
				if(EVP_Cipher(main_evp, xorStream + AADLEN,
				    zeros, KEYSTREAMLEN) < 0) {
					quitting=1;
					break;
				}
				break;
			case 'p' :
				/* read poly_key and keystream */
				/* FALL THROUGH */
			case 'r' :
				/* read keystream */
				if(readInt(&param, textmode)) {
					quitting = 1;
					break;
				}
				if(cmd == 'p') {
					if(fwrite(poly_key, POLY1305_KEYLEN, 1,
					    stdout) != 1) {
						quitting = 1;
						break;
					}
				}
				if(fwrite(xorStream, param + AADLEN, 1, stdout)
				    != 1)
					quitting = 1;
				break;
			default :
				/* unrecognized command */
				quitting = 1;
		}
		if(quitting)
			break;
	}

 cleanup:
	EVP_CIPHER_CTX_free(main_evp);
	EVP_CIPHER_CTX_free(header_evp);
	explicit_bzero(seqbuf,sizeof(seqbuf));
	explicit_bzero(poly_key,sizeof(poly_key));
	explicit_bzero(headerkey,sizeof(headerkey));
	explicit_bzero(mainkey,sizeof(mainkey));
	explicit_bzero(xorStream,sizeof(xorStream));
	explicit_bzero(&param,sizeof(param));
}
