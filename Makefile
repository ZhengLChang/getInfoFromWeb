#Makefile
CC=gcc
INCLUDE=
LIB=-lpthread -lcrypto -liconv
CFLAGS=-g -Wall -Werror -D_REENTRANT -D_GNU_SOURCE ${LIB} ${INCLUDE}
#CFLAGS=-g ${LIB} ${INCLUDE}
MainFile=main.c
#OutPut=$(patsubst %.c, %, ${MainFile})
OutPut=getInfoFromWeb
src=base64.c json.c config.c util.c log.c buffer.c http.c
target=$(patsubst %.c, %.o, ${MainFile})
target+=$(patsubst %.c, %.o, ${src})
springcleaning=$(patsubst %.c, %, $(wildcard ./*.c))
springcleaning+=$(patsubst %.c, %.o, $(wildcard ./*.c))
springcleaning+=$(patsubst %.c, %.o, ${src})
springcleaning+=$(OutPut)

.PHONY: all clean

all: $(OutPut)
$(OutPut):${target}
	$(CC) ${target}  -o $@ ${CFLAGS} ${INCLUDE} 
	
clean:
	-@rm  ${springcleaning}
