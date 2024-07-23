CC = gcc
CFLAGS = -I./include -Wall -Wextra -Werror
PRJ = my_secmalloc
OBJS = src/my_secmalloc.o
SLIB = lib${PRJ}.a
LIB = lib${PRJ}.so
GCOVFLAGS = --coverage
COV_DIR = out

all: ${LIB}

${LIB} : CFLAGS += -fpic -shared
${LIB} : ${OBJS}

${SLIB}: ${OBJS}

dynamic: CFLAGS += -DDYNAMIC
dynamic: ${LIB}

static: ${SLIB}

clean:
	${RM} src/.*.swp src/*~ src/*.o test/*.o src/*.gcda src/*.gcno test/*.gcda test/*.gcno *.info

distclean: clean
	${RM} ${SLIB} ${LIB} test/test
	${RM} -r ${COV_DIR}

build_test: CFLAGS += -DTEST ${GCOVFLAGS}
build_test: ${OBJS} test/test.o
	$(CC) -o test/test $^ -lgit2 -lcriterion -Llib -lgcov

test: build_test
	LD_LIBRARY_PATH=./lib test/test

coverage: test
	lcov --capture --directory ./src --output-file coverage.info
	genhtml coverage.info --output-directory ${COV_DIR}

.PHONY: all clean build_test dynamic test static distclean coverage

%.so:
	$(LINK.c) -shared $^ $(LDLIBS) -o $@

%.a:
	${AR} ${ARFLAGS} $@ $^