#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <malloc.h>

#define UDPPORT 6000

int sock_desc;
struct sockaddr_in thishost_addr;
struct sockaddr_in sender_addr;
socklen_t sock_struct_len = sizeof(thishost_addr);

int main()
{
    char message[1024];
    FILE *fptr;

    /* Create socket */
    sock_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock_desc < 0)
	{
        printf("Error creating socket\n");
        return -1;
    }
    printf("[OK]\tSocket created successfully.\n");

     /* Set port and IP */
    thishost_addr.sin_family = AF_INET;
    thishost_addr.sin_port = htons(UDPPORT);
	//thishost_addr.sin_addr.s_addr = inet_addr(argv[2]);
	thishost_addr.sin_addr.s_addr = htons(INADDR_ANY);

    /* Bind to the set port and IP */
    if(bind(sock_desc, 
            (struct sockaddr*)&thishost_addr, 
            sizeof(thishost_addr)) < 0)
    {
        printf("Couldn't bind to the port\n");
        return -1;
    }
    printf("[OK]\tBinding successful.\n");


    while(1)
    {
        memset(message,'\0',sizeof(message));
        if(recvfrom(sock_desc, 
                    message, 
                    sizeof(message), 
                    0,
                    (struct sockaddr*)&thishost_addr, 
                    &sock_struct_len) < 0)
        {
            printf("Couldn't receive\n");
            return -1;
        }
        //printf("recvd:: %s\n",message);

        /* save in the file */
        /* open file for appending */
        fptr = fopen("data.dat","a");
        if(fptr==NULL)
        {
            printf("Error opening file.\n");
            return -1;
        }
        fprintf(fptr,"%s\n", message);
        fclose(fptr);
    }

    return 0;
}
