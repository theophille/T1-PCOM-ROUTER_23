PROJECT=router
SRCDIR=src/
BUILDDIR=build/
DEPDIR = dep/
SOURCES=src/router.c src/lib/queue.c src/lib/list.c src/lib/lib.c
LIBRARY=nope
INCPATHS=src/include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -Wall -Werror -Wno-error=unused-variable
CC=gcc

# make temporary *.Td dependency files on compilation to avoid ruining the
# existing ones if the compilation fails
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)$*.Td

#
# make the necessary directories to maintain the exact folder hierarchy of the
# SRCDIR, in both BUILDDIR and DEPDIR
#
PRECOMPILE=mkdir -p $(BUILDDIR)$(dir $*); mkdir -p $(DEPDIR)$(dir $*)

# rename the temporary dependency files, making them permanent
POSTCOMPILE = mv -f $(DEPDIR)$*.Td $(DEPDIR)$*.d

# Automatic generation of some important lists
OBJECTS=$(subst $(SRCDIR),$(BUILDDIR),$(SOURCES:%.c=%.o))

INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(BUILDDIR)/$(PROJECT)

all: $(SOURCES) $(BINARY)

$(BINARY): $(OBJECTS)
	$(CC) $(LIBFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILDDIR)%.o: $(SRCDIR)%.c
	$(PRECOMPILE)
	$(CC) $(INCFLAGS) $(CFLAGS) $(DEPFLAGS) -fPIC $< -o $@
	$(POSTCOMPILE)

distclean: clean
	rm -f $(BINARY)

clean:
	rm -rf $(BUILDDIR) $(DEPDIR) router* hosts_output

# include dependency makefiles
-include $(DEPS)
