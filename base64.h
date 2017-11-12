#ifndef BASE64_H_
#define BASE64_H_
ssize_t base64_decode (const char *base64, void *dest);
size_t base64_encode (const void *data, size_t length, char *dest);
static unsigned char * base64_decode_lighttpd(char *out, const char *in);
ssize_t base64_decode_for_big_buffer_to_file(const char *base64, int fd);
ssize_t write_all(int fd, const void *buf, size_t count);
int base64_decode_to_file(const char *in_file, const char *out_file);
int base64_encode_to_file(const char *in_file, const char *out_file);
#endif
