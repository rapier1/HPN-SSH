#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "defines.h"
#include "sshbuf.h"
#include "cipher-chachapoly-forks.h"
#include "ipc.h"

/* #define DEBUGMODE */

#ifdef DEBUGMODE
	#define err(fmt, args...) _err(fmt, ##args)
	#define dumphex(label, data, size) _dumphex(label, data, size)
#else
	#define err(fmt, args...)
	#define dumphex(label, data, size)
#endif

struct smem * sharedmem;
long guess;

int _err(const char * restrict format, ...) {
	va_list arg;
	int done;
	char prefix[64];
	memset(prefix,'\0',sizeof(prefix));
	sprintf(prefix,"DEBUGY(%d): ",getpid());
	char * buf = malloc(strlen(prefix) + strlen(format) + 1);
	memset(buf,'\0',sizeof(buf));
	strcat(buf,prefix);
	strcat(buf,format);
	va_start(arg, format);
	done = vfprintf(stderr, buf, arg);
	va_end(arg);
	free(buf);
	return done;
}

void _dumphex(const u_char * label, const u_char * data, size_t size) {
	char * str = malloc(size * 2 + 1);
	for(u_int i=0; i<size; i++)
		sprintf(str + 2*i, "%02hhx", data[i]);
	err("%s: %s\n", label, str);
	free(str);
}


void discard() {
	char * linebuf;
	size_t size = 1;
	linebuf = malloc(size * sizeof(char));
	if(getline(&linebuf,&size,stdin) == -1) {
		err("Something odd happened.");
	}
	free(linebuf);
}

int readBinLoop(void * result, size_t size) {
	size_t readbytes = -1;
	size_t origsize = size;
	while(size > 0) {
		readbytes = read(STDIN_FILENO,result,size);
		if(readbytes == -1)
			return -1;
		else {
			err("read %lu binary bytes: \n",readbytes);
			dumphex("bytes",result,readbytes);
			size-=readbytes;
		}
	}
	return 0;
}

int readInt(u_int * result, u_char textmode) {
	if (textmode == 0) {
		return readBinLoop(result,sizeof(u_int));
	} else if (textmode == 2) {
		size_t size;
		size = smem_nread_msg(sharedmem, result, sizeof(u_int), HELPSIG);
		if (size != 4)
			return -1;
		else
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
	if (textmode == 2) {
		size_t size;

		guess = smem_gspinwait(sharedmem, 0, guess);
		size = smem_nread_msg(sharedmem, result, sizeof(u_char), HELPSIG);
		if (size == 0) {
			smem_signal(sharedmem, 1);
			guess = smem_gspinwait(sharedmem, 0, guess);
			size = smem_nread_msg(sharedmem, result,
				sizeof(u_char), HELPSIG);
		}
		return 0;
	}
	if(read(STDIN_FILENO,result,sizeof(u_char)) != 1)
		return -1;
	if(textmode)
		discard();
	return 0;
}

int readBytes(u_char * result, size_t size, u_char textmode) {
	if(textmode == 0) {
		return readBinLoop(result, size*sizeof(u_char));
	} else if (textmode == 2) {
		size_t readsize;
		readsize = smem_nread_msg(sharedmem, result, size, HELPSIG);
		if (readsize != size)
			return -1;
		else
			return 0;
	} else {
		char * linebuf = NULL;
		size_t linesize;
		ssize_t r = getline(&linebuf,&linesize,stdin);
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
gen(u_char * poly_key, u_char * xorStream, u_int seqnr,
    EVP_CIPHER_CTX * main_evp, EVP_CIPHER_CTX * header_evp) {
	u_char zeros[KEYSTREAMLEN + AADLEN];
	u_char seqbuf[16];
	int ret;

	ret = 0;
	memset(seqbuf, 0, sizeof(seqbuf));
	memset(zeros, 0, sizeof(zeros));

	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, POLY1305_KEYLEN);

	if (!EVP_CipherInit(main_evp, NULL, NULL, seqbuf, 1)) {
		ret = 1;
		goto out;
	}
	if (EVP_Cipher(main_evp, poly_key, poly_key, POLY1305_KEYLEN) < 0) {
		ret = 1;
		goto out;
	}
	if (!EVP_CipherInit(header_evp, NULL, NULL, seqbuf, 1)) {
		ret = 1;
		goto out;
	}
	if (EVP_Cipher(header_evp, xorStream, zeros, CHACHA_BLOCKLEN) < 0 ) {
		ret = 1;
		goto out;
	}
	seqbuf[0] = 1;
	if (!EVP_CipherInit(main_evp, NULL, NULL, seqbuf, 1)) {
		ret = 1;
		goto out;
	}
	if (EVP_Cipher(main_evp, xorStream + AADLEN, zeros, KEYSTREAMLEN) < 0) {
		ret = 1;
		goto out;
	}
 out:
	if (ret == 1)
		err("failed in g.\n");
	explicit_bzero(seqbuf, sizeof(seqbuf));
	return ret;
}

int
main(int argc, char ** argv) {
	EVP_CIPHER_CTX * main_evp;
	EVP_CIPHER_CTX * header_evp;
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

	main_evp = NULL;
	header_evp = NULL;
	sharedmem = NULL;
	guess = 1;

	if(read(STDIN_FILENO,&textmode, sizeof(textmode)) != 1)
		goto cleanup;
	if(textmode == 'b' || textmode == 'B') {
		textmode = 0;
		err("mode: binary\n");
	} else if (textmode == 't' || textmode == 'T') {
		textmode = 1;
		discard();
		err("mode: text\n");
	} else {
		goto cleanup;
	}

	if(readInt(&streams, textmode))
		goto cleanup;
	err("streams: %u\n",streams);
	if(readInt(&seqnr, textmode))
		goto cleanup;
	err("seqnr: %u\n",seqnr);

	if((main_evp = EVP_CIPHER_CTX_new()) == NULL )
		goto cleanup;
	err("initialized main_evp\n");
	if((header_evp = EVP_CIPHER_CTX_new()) == NULL )
		goto cleanup;
	err("initialized header_evp\n");

	if(readBytes(mainkey, CHACHA_KEYLEN, textmode))
		goto cleanup;
	err("mainkey received\n");
	if(!EVP_CipherInit(main_evp, EVP_chacha20(), mainkey, NULL, 1))
		goto cleanup;
	explicit_bzero(mainkey, sizeof(mainkey));

	if(readBytes(headerkey, CHACHA_KEYLEN, textmode))
		goto cleanup;
	err("headerkey received\n");
	if(!EVP_CipherInit(header_evp, EVP_chacha20(), headerkey, NULL, 1))
		goto cleanup;
	explicit_bzero(headerkey, sizeof(headerkey));

	if(EVP_CIPHER_CTX_iv_length(header_evp) != 16)
		goto cleanup;
	
	quitting = 0;

	err("Entering main loop.\n");

	while(1) {
		if(readChar(&cmd, textmode)) {
			err("Pipe closed\n");
			break;
		}
		err("Start loop.\n");
		switch(cmd) {
			case 'q' :
				/* quit */
				err("received q\n");
				quitting = 1;
				break;
			case 'n' :
				/* increment seqnr */
				err("received n\n");
				seqnr += streams;
				break;
			case 'm' :
				/* switch to shared-memory mode */
				err("received m\n");
				if (sharedmem != NULL)
					break;
				if (readInt(&param, textmode)) {
					err("failed to read parameter.\n");
					quitting = 1;
					break;
				}
				sharedmem = smem_join(param);
				if (sharedmem == NULL) {
					err("failed to map shared memory.\n");
					quitting = 1;
					break;
				}
				err("switched to mem mode.\n");

				textmode = 2;
				break;
			case 'd' :
				err("received d\n");
				ungetc('\n',stdin);
				ungetc('d',stdin);

				ungetc('\n',stdin);
				ungetc('8',stdin);
				ungetc('6',stdin);
				ungetc('7',stdin);
				ungetc('2',stdin);
				ungetc('3',stdin);

				ungetc('\n',stdin);
				ungetc('r',stdin);

				ungetc('\n',stdin);
				ungetc('g',stdin);

				ungetc('\n',stdin);
				ungetc('n',stdin);
				break;
			case 's' :
				err("received s\n");
				if(readInt(&param, textmode)) {
					err("failed to read parameter.\n");
					quitting = 1;
					break;
				}
				seqnr = param;
				break;
			case 'g' :
				/* genererate keystream */
				err("received g\n");
				if (textmode == 2) {
					quitting = gen(sharedmem->data,
					    sharedmem->data + POLY1305_KEYLEN,
					    seqnr, main_evp, header_evp);
				}
				else
					quitting = gen(poly_key, xorStream,
					    seqnr, main_evp, header_evp);
				break;
			case 'p' :
				/* read poly_key and keystream, then advance */
				/* FALL THROUGH */
			case 'r' :
				/* read keystream */
				err("received p / r\n");
				if(readInt(&param, textmode)) {
					err("failed to read parameter.\n");
					quitting = 1;
					break;
				}
				err("parameter: %u\n",param);
				if(cmd == 'p') {
					err("writing poly_key\n");
					int ret;
					if((ret = write(STDOUT_FILENO, poly_key,
					    POLY1305_KEYLEN))
					    != POLY1305_KEYLEN) {
						quitting = 1;
						break;
					}
					err("wrote poly_key: %d bytes\n", ret);
				}
				err("writing xorStream\n");
				if(write(STDOUT_FILENO, xorStream,
				    param + AADLEN) != param + AADLEN)
					quitting = 1;
				err("wrote xorStream\n");
				if(cmd == 'p') {
					err("advancing seqnr\n");
					seqnr += streams;
					err("calling gen\n");
					quitting = gen(poly_key, xorStream,
					    seqnr, main_evp, header_evp);
				}
				break;
			default :
				/* unrecognized command */
				err("unrecognized command\n");
				quitting = 1;
		}
		if(quitting) {
			err("quitting detected.\n");
			break;
		}
	}

 cleanup:
	err("cleaning up.\n");
	EVP_CIPHER_CTX_free(main_evp);
	EVP_CIPHER_CTX_free(header_evp);
	explicit_bzero(poly_key,sizeof(poly_key));
	explicit_bzero(headerkey,sizeof(headerkey));
	explicit_bzero(mainkey,sizeof(mainkey));
	explicit_bzero(xorStream,sizeof(xorStream));
	explicit_bzero(&param,sizeof(param));
	if (sharedmem != NULL)
		smem_leave(sharedmem);
}
