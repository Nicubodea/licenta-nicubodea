#include "stdio_n.h"

unsigned __int64 min(unsigned __int64 a, unsigned __int64 b)
{
    if (a < b)
        return a;
    return b;
}

void memcpys(void* source, void* destination, unsigned __int64 num)
{
    unsigned __int64 i, bufsize, j;
    char buffer[4000];
    for (bufsize = 0; bufsize < num; bufsize += 4000)
    {
        j = 0;
        for (i = bufsize; i < min(bufsize + 4000, num); i++)
        {
            buffer[j] = ((PBYTE)source)[i];
            j++;
        }
        j = 0;
        for (i = bufsize; i < min(bufsize + 4000, num); i++)
        {
            ((PBYTE)destination)[i] = buffer[j];
            j++;
        }
    }
}

int memcmps(char* source, char* source2)
{
    DWORD i = 0;
    while (source[i] != 0 && source2[i] != 0)
    {
        if (source[i] != source2[i])
        {
            return 1;
        }
    }
    if (source[i] == 0 && source2[i] == 0)
    {
        return 0;
    }
    return 1;
}