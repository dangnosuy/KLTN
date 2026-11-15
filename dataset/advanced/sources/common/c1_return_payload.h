#ifndef C1_RETURN_PAYLOAD_H
#define C1_RETURN_PAYLOAD_H

/* A one-byte x64 thread entry that returns to the Windows thread thunk. */
static unsigned char payload[] = { 0xc3 };
static unsigned int payload_len = sizeof(payload);

#endif
