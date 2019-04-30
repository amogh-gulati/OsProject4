#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

static int filesys_inited = 0;
//int log = 0;

struct Node
{
	char block[64];
	char hash[20];
	struct Node *next;
	int fd;
};

struct Node *top;
struct Node *base;

int fc = 0;
/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

void stripHash(char *hash)
{
	for(int i=0;i<19;i++)
	{
		if(hash[i]=='\n')
			hash[i] = 'k';
		if(hash[i] == ' ')
			hash[i] ='l';
	}
}

void doHash(struct Node *head,int size)
{
	struct Node *curr = head;
	while(curr!=NULL)
	{
		get_sha1_hash(curr->block,size,curr->hash);
		curr = curr->next;
	}
}


void makeMerk(struct Node *head,struct Node *carry,int base)
{
	if(head->next==NULL && carry==NULL)
	{
		//this is the top level
		doHash(head,40);
		stripHash(head->hash);
		printf("we have the final hash\n");
		top = head;
		//return;
		if ( top ==NULL)
			top = head;
		else
		{
			head->next = top;
			top = head;
		}
		printf("%s\n",top->hash);
		return;
	}
	//this is the head of the upper level
	struct Node *h = (struct Node*)malloc(sizeof(struct Node));
	h->next = NULL;
	//this is the carry struct
	struct Node *c = NULL;
	//two nodes of the base level
	struct Node *first = head;
	struct Node *second = head->next;
	if(head->next==NULL)
		second = carry;
	//this is the iterator for the lower level
	struct Node *curr = head;
	//this is the builder for the
	struct Node *build = h;
	strcpy(build->block,first->hash);
	strcat(build->block,second->hash);
	curr = second->next;

	while(curr!=NULL)
	{
		if(curr->next==NULL)
		{
			if(carry!=NULL)
			{
				first = curr;
				second = carry;
			}
			else
			{
				c = curr;
				break;
			}
			curr = curr->next;
		}
		else
		{
			first = curr;
			second = curr->next;
			curr = second->next;
		}
		//i have already dealt with curr
		//now i have to deal with build
		struct Node *new = (struct Node*)malloc(sizeof(struct Node));
		new->next = NULL;
		build->next = new;
		build = new;
		strcpy(build->block,first->hash);
		strcat(build->block,second->hash);
		if(base!=1)
        {
		    free(first);
            free(second);
        }
	}
	doHash(h,40);
	makeMerk(h,c,0);
}

int calculateHash(const char *pathname)
{
	//printf("we in calculate hash\n");
	FILE *fptr;
	char ch ;
	fptr = fopen(pathname,"r");
	if(fptr == NULL)
	{
		printf("cannot open file");
		return 2;
	}
	fflush(fptr);
	struct Node *head = (struct Node*)malloc(sizeof(struct Node));
	strcpy(head->block,"dummy value");
	head->next = NULL;
	struct Node *curr = head;
	int count = 0;
	ch = (char)fgetc(fptr);
	//int nomber = 0;
	while(ch!=EOF)
	{
		//printf("%c",ch);
		curr->block[count] = ch;
		count++;
		ch = fgetc(fptr);
		if(count==64)
		{
			//nomber++;
			//now we need a new
			struct Node *new = (struct Node*)malloc(sizeof(struct Node));
			curr->next = new;
			curr = new;
			curr->next = NULL;
			count = 0;
		}
	}

	//printf("\n");
	//struct Node *n = head;
	fclose(fptr);
	doHash(head,64);
	//printf("this is the nomber%d\n",nomber);
	makeMerk(head,NULL,1);
	return 0;
}

//
int checkHash(const char *pathname)
{
    int check = calculateHash(pathname);
    if(check==-1)
    {
        printf("error in calculate hash\n");
        return -1;
    }
    char merkleHash[20];
    strcpy(merkleHash,top->hash);
    int sl = strlen(merkleHash);
    if (sl!=20)
        printf("the size of the hash is not 20 \n");

    FILE *fptr = fopen("secure.txt","r");
    if(fptr == NULL)
    {
        printf("creating open secure\n");
        fptr = fopen("secure.txt","w+");
        if(fptr == NULL)
        {
            printf("unable to make secure.txt\n");
            return -1;
        }
    }
    char secureHash[20];
    char str[64];
    int flag = 0;
    while(!feof(fptr)){
        //int end = fscanf(fptr,"%s",str);
        if(fscanf(fptr,"%s",str)==-1){
            break;
        }
        printf("%s\n",str);
        if(strcmp(str,pathname)==0){
            flag = 1;
            printf("we matched the pathname\n");
            if(fscanf(fptr,"%s",str)==1){
                printf("we have the hash from file %s\n",str);
                int sl = strlen(str);
                if (sl!=20)
                    printf("the size of the hash is not 20 \n");
                //printf("henlo");
                strcpy(secureHash,str);
                //printf("this is the secure hash\n");
                //printf("%s\n",secureHash);
                break;
            }
        }
    }
    if(flag == 0){
        printf("%s was not present in secure.txt\n",pathname);
        fclose(fptr);
        FILE *fptr = fopen("secure.txt","a+");
        if(fptr==NULL)
        {
            printf("Wtf");
            exit(0);
        }
        printf("writing to file secure.txt\n");
        fc++;
        fseek(fptr,0,SEEK_END);
//        fprintf(fptr,"%s",pathname);
//        fprintf(fptr,"%s"," ");
//        fprintf(fptr,"%s",merkleHash);
//        fprintf(fptr,"%s\n"," ");

        fprintf(fptr,"%s %s\n",pathname,merkleHash);
        fclose(fptr);
        return 1;
    }
    fclose(fptr);
    if(strcmp(merkleHash,secureHash)==0){
        return 0;
    }
    else{
        return -1;
    }
}
/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);
	printf("opening the file %s\n",pathname);
	int flag = 0;
	FILE *fptr = fopen(pathname,"r");
	if (fptr==NULL)
	    flag=1;
	else
	    fclose(fptr);
	int fd = open(pathname,flags,mode);
	if (fd==-1)
	{
		printf("s_open was unable to open the file");
		return -1;
	}
	close(fd);
	//to create the file if it was not there
	int check = checkHash(pathname);
	printf("%d\n",check);
    if(check==-1 && flag==0 )
    {
        printf("fails \n");
        top->fd = -1;
        top->block[0] = '\0';
        return -1;
    }
    else
    {
        printf("not fails\n");
        int ret =  open (pathname, flags, mode);
        top->fd = ret;
        strcpy(top->block,pathname);
        return ret;
    }
}


/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	return lseek (fd, offset, SEEK_SET);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
	return write (fd, buf, count);
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	return read (fd, buf, count);
}
//void updateSecure(char pathname[], char replace[]){
//    FILE* f1=fopen("secure.txt","r");
//    FILE* f2=fopen("secure2.txt","w+");
//    char str[64];
//    fseek(f1,0,SEEK_SET);
//    fseek(f2,0,SEEK_SET);
//    while(!feof(f1)){
//        int end = fscanf(f1,"%s",str);
//        printf("%s\n",str);
//        if(end==-1){
//            return;
//        }
//        fprintf(f2,"%s ",str);
//        if(strcmp(str,pathname)==0){
//            printf("we matched the pathname\n");
//            fscanf(f1,"%s",str);
//            fprintf(f2,"%s\n",replace);
//        }
//        else{
//            if(fscanf(f1,"%s",str)!=-1){
//                printf("%s\n",str);
//                fprintf(f2,"%s\n",str);
//            }
//        }
//    }
//    remove("secure.txt");
//    rename("secure2.txt","secure.txt");
//}
void updateSecure(char* filename, char* newhash){

    //FILE *secptr;
    /*   a+
     *   Open for reading and appending (writing at end of file).  The
              file is created if it does not exist.  The initial file
              position for reading is at the beginning of the file, but
              output is always appended to the end of the file.
     */
    //secptr = fopen("secure.txt", "a+");

    int fd1 = open ("secure.txt",O_RDWR,777);

//    int fd2 = open ("set.txt", O_WRONLY | O_CREAT| O_TRUNC,777);
//    if(fd2<0)
//        printf("not working");
    FILE *fptr = fopen("set.txt","w");
    char buf[31];
    int sz = 0;
    printf("in update secure\n");
    //int l = 0;
    for(int i=0;i<fc;i++)
    {
        sz = read(fd1,buf, sizeof(buf));
        printf("%d\n",sz);
        buf[sz] = '\0';
        printf("%s",buf);
        if (strncmp(filename,buf,7)==0)
		{
        	printf("we have a match\n");
        	for(int j=0;j<20;j++)
            {
        	    buf[10+j] = newhash[j];
            }
		}
//        sz = write(fd2,buf, sizeof(buf));
        fprintf(fptr, "%s", buf);
    }
    close(fd1);
    //close(fd2);
    fflush(fptr);
    fclose(fptr);
    remove("secure.txt");
    rename("set.txt", "secure.txt");
    printf("leaving\n");
    return;
//    int line=0;
//    char var1[30];
//    char var2[20];
//    FILE *stream = fopen("secure.txt","r");
//    FILE *ofs = fopen("sEcRet.txt", "w");
//    while(fscanf(stream, "%s %s\n", var1, var2) != EOF) {
//        line++;
//        if(strcmp(filename, var1)==0) {
//            printf("%s %s\n", var1, newhash);
//            fprintf(ofs, "%s %s\n", var1, newhash);
//
//        } else {
//            printf("%s %s\n", var1, var2);
//            fprintf(ofs, "%s %s\n", var1, var2);
//        }
//        if(line==fc)
//            break;
//    }
//    fclose(ofs);
//    fclose(stream);
//    remove("secure.txt");
//    rename("sEcRet.txt", "secure.txt");
}
/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
    int ret =  close (fd);
    struct Node *n = top;
    char hash[20];
    char pathname[64];
    while(n!=NULL)
    {
        if(n->fd==fd)
        {
            strcpy(pathname,n->block);
            break;
        }
        n = n->next;
    }
    calculateHash(pathname);
    strcpy(hash,top->hash);
    printf("closing file %s\n",pathname);
    printf("with hash %s\n",hash);
    updateSecure(pathname,hash);
    return ret;
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	filesys_inited = 1;
    int fd1 = open ("secure.txt",O_RDWR ,777);
    if(fd1<0)
    {
        FILE *stream = fopen("secure.txt","a");
        fclose(stream);
    }
    fd1 = open ("secure.txt",O_RDWR ,777);
    char buf[31];
    int sz = 0;
    printf("in filesys init \n");
    while(1)
    {
        sz = read(fd1,buf, sizeof(buf));
        if(sz< sizeof(buf))
            break;
        printf("%d\n",sz);
        buf[sz] = '\0';
        printf("%s\n",buf);
        char name[10];
        strncpy(name,buf,9);
        name[9] = '\0';
        printf("this is the file %s\n",name);
        int a = calculateHash(name);
        if(a==0)
        {
            char newhash[20];
            for(int j=0;j<20;j++)
                newhash[j]=buf[10+j];
            printf("this is the hash%s\n",newhash);
            if (strncmp(newhash,top->hash,19)==0)
            {
                printf("fine\n");
            }
            else
            {
                printf("the hashes dont match\n");
                return 1;
            }
        }
    }
    close(fd1);
    printf("returning true");
    return 0;
//    char var1[20];
//    char var2[20];
//
//    //FILE *ofs = fopen("sEcRet.txt", "w");
//    while(fscanf(stream, "%s %s\n", var1, var2) != EOF) {
//        printf("this is the file%s\n",var1);
//        calculateHash(var1);
//        printf("%s\n",var2);
//        if(strncmp(var2,top->hash,19)!=0)
//            return 1;
//    }
//    fclose(stream);
//	return 0;
}
