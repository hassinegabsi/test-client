#include <stdio.h>
#include<stdlib.h>
#include<string.h>

int main(int argc, char **argv)
{
    char pcCMDSystem[100];
    memset(pcCMDSystem,0,sizeof(pcCMDSystem));
    int iNbClient =atoi(argv[1]);
    for (int i = 0; i<iNbClient; i++)
    {
        snprintf(pcCMDSystem,sizeof(pcCMDSystem) -1, "./mosquitto_demo %d &",i);
        system(pcCMDSystem);
    } 
return 0;    
}


