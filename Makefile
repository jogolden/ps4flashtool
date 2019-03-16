# golden

ODIR	:= build
CFLAGS	:= -I/usr/include/
CFILES	:=	$(wildcard *.c)
OBJS	:=	$(patsubst %.c, build/%.o, $(CFILES))
LIBS	:= 

TARGET = flashtool

$(TARGET): $(ODIR) $(OBJS)
	gcc -g -o $(TARGET) $(ODIR)/*.o $(CFLAGS) $(LIBS)

$(ODIR)/%.o: %.c
	gcc -g -c -o $@ $< $(CFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean
clean: 
	rm $(TARGET) build/*
