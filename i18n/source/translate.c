#include	<sys/types.h>
#include	<sys/stat.h>

int
main(int argc, char *argv[])
{
	int			fdin, fdout;
	char		*src, *dst;
	struct stat	statbuf;

	if (argc != 3)
		err_quit("usage: a.out <fromfile> <tofile>");

	if ( (fdin = open(argv[1], O_RDONLY)) < 0)
		err_sys("can't open %s for reading", argv[1]);

	if ( (fdout = open(argv[2], O_RDWR | O_CREAT | O_TRUNC,
												FILE_MODE)) < 0)
		err_sys("can't creat %s for writing", argv[1]);

	if (write(fdout, "", 1) != 1)
		err_sys("write error");

	if ( (src = mmap(0, statbuf.st_size, PROT_READ,
					 MAP_FILE | MAP_SHARED, fdin, 0)) == (caddr_t) -1)
		err_sys("mmap error for input");

	exit(0);
}
