#include <stdio.h>
#include <Strn.h>

main()
{
	char a[8];
	char pad1[32];
	char *b;
	char c[37];
	char pad2[23];
	int i;
	int len1, len2;

	b = Strncpy(a, "hello", sizeof(a));
	b = Strncat(b, "world", sizeof(a));
	printf("1: result=[%s] should be=[%s]\n",
		b,
		"hellowo"
	);

	for (i=0; i<sizeof(c); i++)
		c[i] = 'X';
	b = Strncpy(c, "testing", sizeof(c) - 2);
#if (STRN_ZERO_PAD == 1)
	for (i=7; i<sizeof(c) - 2; i++) {
		if (c[i] != '\0') {
			printf("2: did not clear to end of buffer\n");
			break;
		}
	}
#endif
	for (i=sizeof(c) - 2; i<sizeof(c); i++) {
		if (c[i] != 'X') {
			printf("2: overwrote buffer\n");
			break;
		}
	}

	for (i=0; i<sizeof(c); i++)
		c[i] = 'X';
	b = Strncpy(c, "testing", sizeof(c) - 2);
	b = Strncat(b, " still", sizeof(c) - 2);
#if (STRN_ZERO_PAD == 1)
	for (i=13; i<sizeof(c) - 2; i++) {
		if (c[i] != '\0') {
			printf("3: did not clear to end of buffer\n");
			break;
		}
	}
#endif
	for (i=sizeof(c) - 2; i<sizeof(c); i++) {
		if (c[i] != 'X') {
			printf("3: overwrote buffer\n");
			break;
		}
	}

/*--------------*/

	b = Strnpcpy(a, "hello", sizeof(a));
	len1 = (int) (b - a);
	b = Strnpcat(a, "world", sizeof(a));
	len2 = (int) (b - a);
	printf("4: result=[%s] should be=[%s] len1=%d len2=%d\n",
		a,
		"hellowo",
		len1,
		len2
	);

	for (i=0; i<sizeof(c); i++)
		c[i] = 'X';
	b = Strnpcpy(c, "testing", sizeof(c) - 2);
#if (STRN_ZERO_PAD == 1)
	for (i=7; i<sizeof(c) - 2; i++) {
		if (c[i] != '\0') {
			printf("5: did not clear to end of buffer\n");
			break;
		}
	}
#endif
	for (i=sizeof(c) - 2; i<sizeof(c); i++) {
		if (c[i] != 'X') {
			printf("5: overwrote buffer\n");
			break;
		}
	}

	for (i=0; i<sizeof(c); i++)
		c[i] = 'X';
	b = Strnpcpy(c, "testing", sizeof(c) - 2);
	b = Strnpcat(c, " still", sizeof(c) - 2);
#if (STRN_ZERO_PAD == 1)
	for (i=13; i<sizeof(c) - 2; i++) {
		if (c[i] != '\0') {
			printf("6: did not clear to end of buffer\n");
			break;
		}
	}
#endif
	for (i=sizeof(c) - 2; i<sizeof(c); i++) {
		if (c[i] != 'X') {
			printf("6: overwrote buffer\n");
			break;
		}
	}
}
