
void DumpMemory()
{
    int i;
    for (i = 0; i < 256*1024*1024; i++)
    {
        //write this to a file ...
        (*(__int64*)i);
    }
    return;
}