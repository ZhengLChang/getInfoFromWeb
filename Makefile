#Makefile
CC=gcc
INCLUDE=
LIB=-lpthread -lcrypto
#CFLAGS=-g -Wall -Werror -D_REENTRANT ${LIB} ${INCLUDE}
CFLAGS=-g ${LIB} ${INCLUDE}
MainFile=getInfoFromWeb.c
OutPut=$(patsubst %.c, %, ${MainFile})
src=base64.c json.c config.c
target=$(patsubst %.c, %.o, ${MainFile})
target+=$(patsubst %.c, %.o, ${src})
springcleaning=$(patsubst %.c, %, $(wildcard ./*.c))
springcleaning+=$(patsubst %.c, %.o, $(wildcard ./*.c))
springcleaning+=$(patsubst %.c, %.o, ${src})

.PHONY: all clean

all: $(OutPut)
$(OutPut):${target}
	$(CC) ${target}  -o $@ ${CFLAGS} ${INCLUDE} 
	
clean:
	-@rm  ${springcleaning}
