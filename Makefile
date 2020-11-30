.PHONY: add_targets clean

ARCHS=$(shell grep '^\[target' .cargo/config | cut -d '.' -f2 | cut -d ']' -f1)

all: $(ARCHS)

add_targets: 
	@echo $(ARCHS) | xargs rustup target add 

$(ARCHS):
	cargo build --target $@

clean:
	cargo clean
	
