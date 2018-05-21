#include "stdio_n.h"
#include "acpica.h"
#define PORT 0x2f8 // com1 port
extern void  write_to_port_char(int a, char b);
extern int read_from_port(int port);
int INITIALISED_PORT = 0;
ACPI_SPINLOCK loglock;
extern int doneAcpica;

void init_serial() {
    AcpiOsCreateLock(&loglock);
    write_to_port_char(PORT + 1, 0x00);    // Disable all interrupts
    write_to_port_char(PORT + 3, 0x80);    // Enable DLAB (set baud rate divisor)
    write_to_port_char(PORT + 0, 0x01);    // Set divisor to 1 (lo byte) 115200 baud
    write_to_port_char(PORT + 1, 0x00);    //                  (hi byte)
    write_to_port_char(PORT + 3, 0x03);    // 8 bits, no parity, one stop bit
    write_to_port_char(PORT + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
    write_to_port_char(PORT + 4, 0x01);    // IRQs enabled, RTS/DSR set
    INITIALISED_PORT = 1;
}

int is_transmit_empty() {
    return read_from_port(PORT + 5) & 0x20;
}

void write_char_port(char a)
{
    if (0 == INITIALISED_PORT)
        init_serial();
    while (0 == is_transmit_empty());
    write_to_port_char(PORT, a);
}

void write_string_port(char* a)
{
    if (0 == INITIALISED_PORT)
        init_serial();
    for (int i = 0; i < strlen(a); i++)
    {
        write_char_port(a[i]);
    }
}

void log_message(char* x)
{
    //log function
    void* argv[5];
    char buffer[100];
    unsigned __int64 tsc = __rdtsc();
    argv[0] = (void*)&tsc;
    
    sprintf_f((PBYTE)buffer, (PBYTE)"%l", argv); // add current processor timestamp
   
    write_string_port("[");
    
    write_string_port(buffer);
    
    write_string_port("] ");
    write_string_port(x); // add message
    
    write_string_port("\r\n"); //new line
}

char gBuffer[1024];
char gBuffer2[1024];
void prelog(char* file, int line, char * x, ...)
{
    if(doneAcpica)
        AcpiOsAcquireLock(loglock);

    va_list y;
    va_start(y, x);
    void* argv[101];
    int args = 0;
    for (int i = 0; i < strlen(x); i++)
    {
        if ('%' == x[i])
        {
            argv[args] = y;
            args++;
            y = y + 8;
        }
    }

    sprintf_f(gBuffer, x, argv);
    argv[0] = &file;
    argv[1] = &line;
    char* pnt = gBuffer;
    argv[2] = &pnt;
    
    sprintf_f(gBuffer2, "%s:%d: %s", argv);

    log_message(gBuffer2);
    if(doneAcpica)
        AcpiOsReleaseLock(loglock, 0);
}

