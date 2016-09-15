BUILD = .

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, $(BUILD)/%.o, $(SRC))
DEPEND = $(patsubst %.c, $(BUILD)/%.d, $(SRC))
LDSCRIPT = $(patsubst %.ld, -T%.ld, $(wildcard *.ld))

.PRECIOUS: $(DEPEND)

INC = -Iinc -I../libnl-3.2.21/include # fix libnl3 package
CFLAGS += -std=c99 -D_GNU_SOURCE $(INC) -rdynamic -fPIE
LDFLAGS += -pie

LDLIBS += -lpthread -lrt -ljson-c -lubus -lubox -lblobmsg_json -luci -liwinfo \
    -lnl-3 -lnl-route-3 -lnl-genl-3 -lmicrohttpd -luuid -lcrypt

TARGETS = $(BUILD)/nakd

all: $(TARGETS)

-include $(DEPEND)

$(BUILD)/nakd: $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) $(LDSCRIPT) -o $@

$(BUILD)/%.d: %.c
	$(CC) $(CFLAGS) -MM $< -o $(BUILD)/$*.d

$(BUILD)/%.o: %.c $(BUILD)/%.d
	$(CC) -c $(CFLAGS) $< -o $(BUILD)/$*.o

clean:
	rm -f $(TARGETS) $(OBJ) $(DEPEND)

.PHONY: all clean
.DEFAULT: all
