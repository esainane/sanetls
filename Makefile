
PREFIX=/usr/local
LIB_NAME=sanetls
LIB_DIR=$(PREFIX)/lib/lib$(LIB_NAME)/interpose
BIN_DIR=$(PREFIX)/bin
LIB_TARGET=lib$(LIB_NAME).so
INSTALL=install -p
SCRIPT=sanetls
DHSIZE=4096
DHFILE=dh_param_$(DHSIZE).pem

all: $(LIB_TARGET) $(SCRIPT) $(DHFILE)

$(LIB_TARGET): sanetls.c
	$(CC) -rdynamic -g -ldl -Wl,-soname,$(LIB_TARGET) -fPIC -shared -o $(LIB_TARGET) sanetls.c

$(SCRIPT): Makefile sanetls.template
	printf '$(shell sed 's_$$_\\n_g' sanetls.template | tr -d \\n)' "$(SCRIPT)" "$(LIB_DIR)" "$(LIB_TARGET)" > sanetls
	chmod +x sanetls

$(DHFILE):
	openssl dhparam $(DHSIZE) -out $(DHFILE)

install: $(LIB_TARGET) $(SCRIPT) $(DHFILE)
	mkdir -p $(LIB_DIR)
	$(INSTALL) -m 644 $(LIB_TARGET) $(LIB_DIR)
	$(INSTALL) -m 644 $(DHFILE)     $(LIB_DIR)
	$(INSTALL) -m 755 $(SCRIPT)     $(BIN_DIR)

clean:
	$(RM) $(LIB_TARGET) $(SCRIPT)

# Note: Regenerating dhparams takes a very long time. You probably don't want to use this.
purge:
	$(RM) $(LIB_TARGET) $(SCRIPT) $(DHFILE)
