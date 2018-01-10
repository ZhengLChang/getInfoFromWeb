#ifndef BASE64_H_
#define BASE64_H_
/* How many bytes it will take to store LEN bytes in base64.  */
#define BASE64_LENGTH(len) (4 * (((len) + 2) / 3))
#define MD5_HASHLEN 16

ssize_t base64_decode (const char *base64, void *dest);
size_t base64_encode (const void *data, size_t length, char *dest);
static unsigned char * base64_decode_lighttpd(char *out, const char *in);
ssize_t base64_decode_for_big_buffer_to_file(const char *base64, int fd);
ssize_t write_all(int fd, const void *buf, size_t count);
int base64_decode_to_file(const char *in_file, const char *out_file);
int base64_encode_to_file(const char *in_file, const char *out_file);

char *digest_authentication_encode (const char *au, const char *user,
                              const char *passwd, const char *method,
                              const char *path);
#endif
