ifeq ($(wildcard asmopt.mak),)
$(error Run ./configure first)
endif

include asmopt.mak

##########################
# set up variables
#

BASEDIR = .
INCLUDE = $(addprefix -I$(BASEDIR)/,src)
CINCLUDE = $(INCLUDE)
ASMINCLUDE = $(INCLUDE)

COMMA := ,
ASMINCLUDE += $(addprefix -Wa$(COMMA),$(INCLUDE))

##########################
# expand all source file paths in to object files
#
OBJASM = poly1305.o
OBJSHARED = main_shared.o

##########################
# non-file targets
#
.PHONY: all
.PHONY: default
.PHONY: lib
.PHONY: shared

.PHONY: install-shared
.PHONY: install-generic
.PHONY: install-lib
.PHONY: uninstall

.PHONY: clean
.PHONY: distclean


all: default

default: lib

install-generic:
	$(INSTALL) -d $(includedir)/libpoly1305
	$(INSTALL) -d $(libdir)
	$(INSTALL) -m 644 src/poly1305.h $(includedir)/libpoly1305

lib: poly1305$(STATICLIB)
	@echo built [poly1305$(STATICLIB)]

install-lib: lib install-generic
	$(INSTALL) -m 644 poly1305$(STATICLIB) $(libdir)
	$(if $(RANLIB), $(RANLIB) $(libdir)/poly1305$(STATICLIB))

ifeq ($(HAVESHARED),yes)
shared: $(SONAME)
	@echo built [$(SONAME)]

install-shared: shared install-generic
ifneq ($(SOIMPORT),)
	$(INSTALL) -d $(bindir)
	$(INSTALL) -m 755 $(SONAME) $(bindir)
	$(INSTALL) -m 644 $(SOIMPORT) $(libdir)
else ifneq ($(SONAME),)
	$(INSTALL) -m 755 $(SONAME) $(libdir)
	ln -f -s $(libdir)/$(SONAME) $(libdir)/libpoly1305.$(SOSUFFIX)
endif
else
shared:
	@echo project must be /configured with --pic

install-shared:
	@echo project must be /configured with --pic
endif # HAVESHARED

uninstall:
	rm -rf $(includedir)/libpoly1305
	rm -f $(libdir)/poly1305$(STATICLIB)
ifneq ($(SOIMPORT),)
	rm -f $(bindir)/$(SONAME) $(libdir)/lib$(SOIMPORT)
else ifneq ($(SONAME),)
	rm -f $(libdir)/$(SONAME) $(libdir)/libpoly1305.$(SOSUFFIX)
endif

clean:
	@rm -f *.o
	@rm -f poly1305$(STATICLIB)
	@rm -f $(SONAME)
	@rm -f $(SOIMPORT)
	@rm -f *.P
	@echo cleaning project [poly1305]

distclean: clean
	@rm asmopt.mak
	@rm src/asmopt.h
	@rm config.log

##########################
# build rules for files
#

# use $(BASEOBJ) in build rules to grab the base path/name of the object file, without an extension
BASEOBJ = $*

# building .S (assembler) files
%.o: src/%.S
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $(ASMINCLUDE) -MMD -MF $(BASEOBJ).temp -D BUILDING_ASM -c -o $(BASEOBJ).o $<
	@cp $(BASEOBJ).temp $(BASEOBJ).P
	@sed \
	-e 's/^[^:]*: *//' \
	-e 's/ *\\$$//' \
	-e '/^$$/ d' \
	-e 's/$$/ :/' \
	< $(BASEOBJ).temp >> $(BASEOBJ).P
	@rm -f $(BASEOBJ).temp

# building .c (C) files
%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CINCLUDE) -MMD -MF $(BASEOBJ).temp -c -o $(BASEOBJ).o $<
	@cp $(BASEOBJ).temp $(BASEOBJ).P
	@sed \
	-e 's/#.*//' \
	-e 's/^[^:]*: *//' \
	-e 's/ *\\$$//' \
	-e '/^$$/ d' \
	-e 's/$$/ :/' \
	< $(BASEOBJ).temp >> $(BASEOBJ).P
	@rm -f $(BASEOBJ).temp

##########################
# include all auto-generated dependencies
#

-include $(OBJASM:%.o=%.P)
-include $(OBJSHARED:%.o=%.P)

##########################
# final build targets
#
poly1305$(STATICLIB): $(OBJASM)
	rm -f poly1305$(STATICLIB)
	$(AR)$@ $(OBJASM)
	$(if $(RANLIB), $(RANLIB) $@)

ifeq ($(HAVESHARED),yes)
$(SONAME): $(OBJASM) $(OBJSHARED)
	$(LD)$@ $(OBJASM) $(OBJSHARED) $(SOFLAGS) $(LDFLAGS)
endif
