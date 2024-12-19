# (c) Vladislav Tislenko (keklick1337), 19 Dec 2024
# Makefile
# This Makefile compiles src/gen_key.cpp into bin/gen_key,
# loading configuration from Makefile.config if present,
# and placing the final binary in bin/.

CXX ?= g++
CFLAGS ?= -O3 -std=c++11
LIBS ?= -lssl -lcrypto -lsecp256k1
INC_FLAGS ?=
LIB_FLAGS ?=

-include Makefile.config

SRCDIR = src
BINDIR = bin
OBJDIR = obj

SOURCES = $(SRCDIR)/gen_key.cpp $(SRCDIR)/addresses.cpp $(SRCDIR)/utils.cpp $(SRCDIR)/config.cpp
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/gen_key

all: $(TARGET)

$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CXX) $(CFLAGS) $(INC_FLAGS) $(OBJECTS) $(LIB_FLAGS) $(LIBS) -o $(TARGET)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	mkdir -p $(OBJDIR)
	$(CXX) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(TARGET)
	rmdir $(OBJDIR) $(BINDIR) 2>/dev/null || true
