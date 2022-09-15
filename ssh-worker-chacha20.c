#include "includes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>

#include "defines.h"
#include "sshbuf.h"
#include "cipher-chachapoly-forks.h"

/* #define DEBUGMODE */

#ifdef DEBUGMODE
	#define err(fmt, args...) _err(fmt, ##args)
#else
	#define err(fmt, args...)
#endif

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

void dumphex(const u_char * label, const u_char * data, size_t size) {
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
	getline(&linebuf,&size,stdin);
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
	if(!textmode) {
		return readBinLoop(result,sizeof(u_int));
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
	if(read(STDIN_FILENO,result,sizeof(u_char)) != 1)
		return -1;
	if(textmode)
		discard();
	return 0;
}

int readBytes(u_char * result, size_t size, u_char textmode) {
	if(!textmode) {
		return readBinLoop(result, size*sizeof(u_char));
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


	if(read(STDIN_FILENO,&textmode, sizeof(textmode)) != 1)
		goto cleanup;
	if(textmode == 'b' || textmode == 'B') {
		textmode = 0;
	} else if (textmode == 't' || textmode == 'T') {
		textmode = 1;
		discard();
	} else {
		goto cleanup;
	}
	err("mode: %s\n",textmode ? "text" : "binary");

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
				memset(seqbuf,0,sizeof(seqbuf));
				POKE_U64(seqbuf+8,seqnr);
				memset(poly_key,0,sizeof(poly_key));
				if(!EVP_CipherInit(main_evp, NULL, NULL, seqbuf,
				    1)) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				if(EVP_Cipher(main_evp, poly_key, poly_key,
				    sizeof(poly_key)) < 0) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				if(!EVP_CipherInit(header_evp, NULL, NULL,
				    seqbuf, 1)) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				if(EVP_Cipher(header_evp, xorStream, zeros,
				    CHACHA_BLOCKLEN) < 0 ) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				seqbuf[0] = 1;
				if(!EVP_CipherInit(main_evp, NULL, NULL, seqbuf,
				    1)) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				if(EVP_Cipher(main_evp, xorStream + AADLEN,
				    zeros, KEYSTREAMLEN) < 0) {
					err("failed in g.\n");
					quitting=1;
					break;
				}
				break;
			case 'p' :
				/* read poly_key and keystream */
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
	explicit_bzero(seqbuf,sizeof(seqbuf));
	explicit_bzero(poly_key,sizeof(poly_key));
	explicit_bzero(headerkey,sizeof(headerkey));
	explicit_bzero(mainkey,sizeof(mainkey));
	explicit_bzero(xorStream,sizeof(xorStream));
	explicit_bzero(&param,sizeof(param));
}
