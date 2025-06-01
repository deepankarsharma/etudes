ODIN := odin
ODIN_FLAGS := -o:speed -no-bounds-check

.PHONY: all clean uring_disk_io

all: uring_disk_io

uring_disk_io: uring_disk_io.odin
	$(ODIN) build $< -file -out:$@ $(ODIN_FLAGS)

clean:
	rm -f uring_disk_io