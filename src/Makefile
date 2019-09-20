MODIFIED_D := $(shell date +%F)
MODIFIED_T := $(shell date +%T)
MODIFIED    = "\"$(MODIFIED_D) $(MODIFIED_T)"\"

INC = -I ./ 
LIBS = -L ./ -lpthread -lssl -lcrypto 


CC = gcc 
CFLAGS = -W -Wall -g -fstack-protector -DUSETLS
#CFLAGS = -W -Wall -O2 -fno-strict-aliasing 
OBJS1 = server.o
OBJS2 = client.o

TARGET1 = tls-server
TARGET2 = tls-client

all:$(TARGET1) $(TARGET2)
.c.o:
	$(CC) -DVERSION=$(MODIFIED) -c $(CFLAGS) $< $(INC)
$(TARGET1):$(OBJS1)
	$(CC) -o $@ $(OBJS1) $(INC) $(LIBS)
	ctags *
	cp $@ ../bin/

$(TARGET2):$(OBJS2)
	$(CC) -o $@ $(OBJS2) $(INC) $(LIBS)
	ctags *
	cp $@ ../bin/
clean:
	rm -f $(TARGET1)
	rm -f $(TARGET2)
	rm -f tags
	rm -f *.o
