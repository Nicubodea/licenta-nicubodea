#include "stdio_n.h"
#include "acpica.h"

unsigned __int64 strlens(PBYTE str)
{
    unsigned __int64 number;
    number = 0;
    while (str[number] != '\0')
        number++;
    return number;
}

void printf(PBYTE format, ...)
{
    va_list x;
    va_start(x, format);
    void* argv[101];
    int args = 0;
    for (int i = 0; i < strlen(format); i++)
    {
        if ('%' == format[i])
        {
            argv[args] = x;
            args++;
            x = x + 8;
        }
    }

    printf_f(format, argv);

}

void sprintf(PBYTE str, const PBYTE format, ...)
{
    va_list x;
    va_start(x, format);
    void* argv[101];
    int args = 0;
    for (int i = 0; i < strlen(format); i++)
    {
        if ('%' == format[i])
        {
            argv[args] = x;
            args++;
            x = x + 8;
        }
    }

    sprintf_f(str, format, argv);
}


int sprintf_f(PBYTE str, const PBYTE format, void* argv[])
{
    unsigned __int64 len;
    unsigned int i, number, cBuffer, j;
    int counterArgs, inverted;
    unsigned __int64  number64;
    char frm;
    counterArgs = -1;
    len = strlens((PBYTE)format);
    cBuffer = 0;

    for (i = 0; i < len; i++)
    {
        if ('%' == format[i])
        {
            
            counterArgs++;
            frm = format[i + 1];
            i++;
            if (frm != 'd' && frm != 's' && frm != 'c' && frm != 'l' && frm!='x')
                return -1;
            if ('d' == frm)
            {
                number = *((unsigned int*)argv[counterArgs]);
                
                inverted = 0;
                char auxi[16];
                if (number <= 0)
                {
                    inverted = 1;
                    auxi[0] = '0';
                }
               
                while (number > 0)
                {
                    auxi[inverted] = number % 10 + 48;
                    inverted++;
                    number = number / 10;
                }
                inverted--;
                while (inverted >= 0)
                {
                    
                    str[cBuffer] = auxi[inverted];
                    inverted--;
                    cBuffer++;
                }

            }
            else if ('s' == frm)
            {
                char* x = (*((char**)argv[counterArgs]));
                for (j = 0; j < strlen(x); j++)
                {
                    str[cBuffer] = x[j];
                    cBuffer++;
                   
                }
                
            }
            else if ('c' == frm)
            {
                str[cBuffer] = *((PBYTE)argv[counterArgs]);
                cBuffer++;
            }
            else if ('l' == frm)
            {
                number64 = *((unsigned __int64*)argv[counterArgs]);
                inverted = 0;
                char auxi[32];
                if (0LL == number64)
                {
                    inverted = 1;
                    auxi[0] = '0';
                }
                while (number64 > 0LL)
                {
                    auxi[inverted] = number64 % 10LL + 48;
                    inverted++;
                    number64 = number64 / 10LL;
                }
                inverted--;
                while (inverted >= 0)
                {
                    str[cBuffer] = auxi[inverted];
                    inverted--;
                    cBuffer++;
                }

            }
            else if ('x' == frm)
            {
                number64 = *((unsigned __int64*)argv[counterArgs]);
                inverted = 0;
                char auxi[32];
                if (0LL == number64)
                {
                    inverted = 1;
                    auxi[0] = '0';
                }
                while (number64 > 0LL)
                {
                    int current = number64 % 16LL;
                    if (current < 10)
                    {
                        auxi[inverted] = number64 % 16LL + 48;
                        inverted++;
                    }
                    else if (10 == current)
                    {
                        auxi[inverted] = 'A';
                        inverted++;
                    }
                    else if (11 == current)
                    {
                        auxi[inverted] = 'B';
                        inverted++;
                    }
                    else if (12 == current)
                    {
                        auxi[inverted] = 'C';
                        inverted++;
                    }
                    else if (13 == current)
                    {
                        auxi[inverted] = 'D';
                        inverted++;
                    }
                    else if (14 == current)
                    {
                        auxi[inverted] = 'E';
                        inverted++;
                    }
                    else if (15 == current)
                    {
                        auxi[inverted] = 'F';
                        inverted++;
                    }
                    number64 = number64 / 16LL;
                }
                inverted--;
                while (inverted >= 0)
                {
                    str[cBuffer] = auxi[inverted];
                    inverted--;
                    cBuffer++;
                }
            }
        }
        else
        {
            str[cBuffer] = format[i];
            cBuffer++;
        }
    
    }
    str[cBuffer] = '\0';
    str[cBuffer + 1] = '\0';
    return 0;


}


PBYTE address = (PBYTE)START_CONSOLE;
int currentColumn = 0;


void printf_f(const PBYTE format, void* argv[])
{
    BYTE buffer[1024];
    sprintf_f((PBYTE)buffer, format, argv);

    int i, j;
    PBYTE addr = address;
    unsigned __int64 len = strlens(buffer);
    
    for (i = 0; i < len; i++)
    {
        if ((unsigned __int64)(PBYTE)addr >= END_CONSOLE)
        {

            memcpys((void*)SECOND_ROW, (void*)START_CONSOLE, 3840);
            for (unsigned __int64 index = END_SECOND_ROW; index < END_CONSOLE; index += 2)
            {
                sprintf_f((PBYTE)index, (PBYTE)" \7", NULL);
            }
            addr -= 160;
        }
        if ('\n' == buffer[i])
        {
            for (j = currentColumn ; j < 80; j++)
            {
                sprintf_f(addr, (PBYTE)" ", NULL);
                addr++;
                sprintf_f(addr, (PBYTE)"\7", NULL);
                addr++;
            }
            currentColumn = 0;
            continue;
        }
        BYTE aux[2];
        aux[0] = buffer[i];
        aux[1] = '\0';
        sprintf_f(addr, aux, NULL);
        addr++;
        sprintf_f(addr, (PBYTE)"\7", NULL);
        addr++;
       
        currentColumn++;
        if (currentColumn >= 80)
            currentColumn = 0;
    }
    address = addr;
}
