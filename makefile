OPTIONS := -flto -O3 -Wall -Wextra -Wshadow -Werror -Wno-unused-function -std=c99

.PHONY: all clean debug ddebug test

all: ramcachefs

clean:
	@rm -f ramcachefs

debug: OPTIONS += -g -DDEBUG -O0
debug: ramcachefs

ddebug: OPTIONS += -g -DDEBUG -DDEBUG_DETAILS -O0
ddebug: ramcachefs

test: OPTIONS += -DDEBUG -DDEBUG_DETAILS
test: test.sh ramcachefs
	@echo "Running $@..."
	@bash $<

ramcachefs: ramcachefs.c
	@echo "Building $@..."
	@$(CC) $< -o $@ `pkg-config fuse3 --cflags --libs` $(OPTIONS)
