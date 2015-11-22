Kerberos over PKCS \#11
=======================

>   *This is a demonstration of Kerberos running over PKCS \#11.  It does little
>   more than take one of its modern ciphers, aes128-cts, and demonstrate that
>   this can be implemented on AES in CBC mode as offered over PKCS \#11.  To
>   this end, it aims to reproduce the test vectors from Appendix B of RFC
>   3962.*

The test does the following:

-   Load the AES-128 key into the PKCS \#11 library as a session key;

-   For each test, run the input string through CKM\_AES\_CBC and glue the data
    to make it act like CTS, and store that as output.

-   For each test, take the stored output, decrypt it with two CKM\_AES\_CBC
    operations with some glue to form a reproduced input.

-   Print each of the test vectors in the precise format used in [Appendix B of
    RFC 3962](<https://tools.ietf.org/html/rfc3962#appendix-B>), which provides
    test vectors.

-   When printing, not the original input is printed, but the reproduced input.

The test demonstrates the following:

-   The elementary encryption algorithm AES-128 in CBC-CTS mode, as it is
    commonly used in Kerberos5, can be implemented on top of PKCS \#11.

-   It is safe to assume that the same applies to AES-256 in CBC-CTS mode.

-   This means that it is possible to store a Kerberos EncryptionKey on a
    hardware token, protected by PKCS \#11.

-   When the "diff" operation produces no output, it indicates that there
    are no differences between the program output and the text that was
    taken from RFC 3962 (and which has only been edited to the extent of
    removing page breaks and text before and after the test vectors).

The demands to a PKCS \#11 token are fairly mild:

-   It must support symmetric key type CKK\_AES and the CKM\_AES\_CBC method.

-   We tested with SoftHSMv2.

-   Modify the Makefile to include and link your favourite PKCS \#11
    implementation.
