#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>

#define WHITESPACE " \t\n"      // We want to split our command line up into tokens
                                // so we need to define what delimits our tokens.
                                // In this case  white space
                                // will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255    // The maximum command-line size

#define MAX_NUM_ARGUMENTS 32    

struct __attribute__((__packed__)) DirectoryEntry {
  char DIR_Name[11]; 
  uint8_t DIR_Attr;
  uint8_t Unused1[8];
  uint16_t DIR_FirstClusterHigh;  
  uint8_t Unused2[4]; 
  uint16_t DIR_FirstClusterLow; 
  uint32_t DIR_FileSize;  
};
struct DirectoryEntry dir[16];

char BS_OEMName[8];
uint16_t BPB_BytesPerSec;
uint8_t BPB_SecPerClus;
uint16_t BPB_RsvdSecCnt;
uint8_t BPB_NumFATs;
uint16_t BPB_RootEntCnt;
char BS_VolLab[11];
uint32_t BPB_FATSz32;
uint32_t BPB_RootClus;
uint16_t BPB_ExtFlags;
uint16_t BPB_FSInfo; 

uint32_t RootDirSectors = 0;
uint32_t FirstDataSector = 0;
uint32_t FirstSectorofCluster = 0;

FILE *fp =NULL;
uint32_t currentCluster = 0;


int LBAToOffset(int32_t sector)
{
  return ((sector - 2) * BPB_BytesPerSec) + (BPB_BytesPerSec * BPB_RsvdSecCnt) + 
  (BPB_NumFATs * BPB_FATSz32 * BPB_BytesPerSec); 
}

int32_t NextLB(uint32_t sector) {
  uint32_t FATAddress = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (sector * 4);
  int32_t val;
  fseek(fp, FATAddress, SEEK_SET);

  //Max 28 (0x0FFFFFFF) of 32 (4) bits
  //to list all of ls
  fread(&val, 4, 1, fp);
  return val & 0x0FFFFFFF;
}


int compare(char *userinput, char *IMG_Name) {
  //extended array for 12 chars

  //prevent token[1] mods
  char name[13];
  memset(&name,0, 13);
  //after memcoph, name will be null terminated
  memcpy(name, userinput,12);
  
  char expanded_name[13];
  memset( expanded_name, ' ', 13 );
  char *token = strtok( name, "." );

  strncpy( expanded_name, token, strlen( token ) );
  token = strtok( NULL, "." );

  if( token ) {
    strncpy( (char*)(expanded_name+8), token, strlen(token ) );
  }

  expanded_name[12] = '\0';

  int i;
  for( i = 0; i < 12; i++ ) {
    expanded_name[i] = toupper( expanded_name[i] );
  }

  if( strncmp( expanded_name, IMG_Name, 12 ) == 0 ) {
    return 1;
  }

  return 0;
}

void closeImg(){

  printf("File system image is closed.\n");
  fclose(fp);
  fp = NULL;
} 

void infoImg(){
  printf("BPB_BytsPerSec:\t0x%X\t%d\n", BPB_BytesPerSec, BPB_BytesPerSec);
  printf("BPB_SecPerClus:\t0x%X\t%d\n", BPB_SecPerClus, BPB_SecPerClus);
  printf("BPB_RsvdSecCnt:\t0x%X\t%d\n", BPB_RsvdSecCnt, BPB_RsvdSecCnt);
  printf("BPB_NumFATs:\t0x%X\t%d\n", BPB_NumFATs, BPB_NumFATs);
  printf("BPB_FATSz32:\t0x%X\t%d\n", BPB_FATSz32, BPB_FATSz32);
  printf("BPB_ExtFlags:\t0x%X\t%d\n", BPB_ExtFlags, BPB_ExtFlags);
  printf("BPB_RootClus:\t0x%X\t%d\n", BPB_RootClus, BPB_RootClus);
  printf("BPB_FSInfo:\t0x%X\t%d\n", BPB_FSInfo, BPB_FSInfo);
}

void readDirectory(uint32_t cluster, struct DirectoryEntry *dirEntry) {
  //start of the cluster
  if (cluster == 0) {
    cluster = BPB_RootClus;
  }

  //current cluster
  uint32_t offset = LBAToOffset(cluster);
  fseek(fp, offset, SEEK_SET);
  fread(dirEntry, sizeof(struct DirectoryEntry), 16, fp);
}

void lsImg(){
  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }
  
  // end of cluster > 0x0FFFFFF8
  while (cluster < 0x0FFFFFF8) {

    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {

      //skip deleted
      if ((uint8_t)dir[i].DIR_Name[0] == 0xE5) {
        continue;
      }
      
      // Skip volumen, hidden, system
      if (dir[i].DIR_Attr == 0x08 || dir[i].DIR_Attr & 0x02 || 
          dir[i].DIR_Attr & 0x04) {
        continue;
      }

      // Print direcotry, d, archive, a
      if (dir[i].DIR_Attr & (0x10 | 0x20)) {
        char name[12];
        memset(&name, 0, sizeof(name));
        memcpy(name, dir[i].DIR_Name, 11);
        printf("%s\n", name);
      }
    }

    cluster = NextLB(cluster);
  }
}

void openImg(char* filename){
  if(filename == NULL){
    printf("Error: File system image not found.\n");
    return;
  }
  if(access(filename, F_OK) == -1) {
    printf("Error: File system image not found.\n");
    return;
  }
  
  fp = fopen(filename, "r+");
  if(fp == NULL) {
    printf("Error: File system image not found.\n");
    exit(1);
  }
  
  printf("File system image %s is opened.\n", filename);

  fseek(fp, 11, SEEK_SET);
  fread(&BPB_BytesPerSec, 2, 1, fp);

  fseek(fp, 13, SEEK_SET);
  fread(&BPB_SecPerClus, 1, 1, fp);

  fseek(fp, 14, SEEK_SET);
  fread(&BPB_RsvdSecCnt, 2, 1, fp);

  fseek(fp, 16, SEEK_SET);
  fread(&BPB_NumFATs, 1, 1, fp);

  fseek(fp, 36, SEEK_SET);
  fread(&BPB_FATSz32, 4, 1, fp);

  fseek(fp, 40, SEEK_SET);
  fread(&BPB_ExtFlags, 2, 1, fp);

  fseek(fp, 44, SEEK_SET);
  fread(&BPB_RootClus, 4, 1, fp);

  fseek(fp, 48, SEEK_SET);  
  fread(&BPB_FSInfo, 2, 1, fp);

  currentCluster = BPB_RootClus;
  readDirectory(currentCluster, dir);
}

void statImg( char *token[]){
    if (token[1] == NULL) {
    printf("Error: No filename specified\n");
    return;
  }

  uint32_t cluster;
  if (currentCluster == 0) {
      cluster = BPB_RootClus;
  } else {
      cluster = currentCluster;
  }

  int found = 0;

  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {

      //0x00 free entry, 0xE5 deleted entry
      if (dir[i].DIR_Name[0] == 0x00 || (uint8_t)dir[i].DIR_Name[0] == 0xE5) {
        continue;
      }

      if (compare(token[1], dir[i].DIR_Name)) {
        found = 1;
        char name[12];
        memset(name, 0, sizeof(name));
        memcpy(name, dir[i].DIR_Name, 11);
        printf("Attribute: %d\n", dir[i].DIR_Attr);
        printf("Size: %d\n", dir[i].DIR_FileSize);
        printf("Starting Cluster Number: %d\n", dir[i].DIR_FirstClusterLow);
        return;
      }
    }

    cluster = NextLB(cluster);
  }

  if (!found) {
    printf("Error: File not found\n");
  }

} 

void cdImg(char *token[]) {

  // to root directory
  if (strcmp(token[1], "/") == 0) {
    currentCluster = BPB_RootClus;
    return;
  }

  // stay in current directory
  if (strcmp(token[1], ".") == 0) {
    return;
  }

  // to parent directory
  if (strcmp(token[1], "..") == 0) {
    if (currentCluster == BPB_RootClus) {
      return;
    }
    
    readDirectory(currentCluster, dir);
    uint32_t parentCluster = dir[1].DIR_FirstClusterLow;
    if (parentCluster == 0) {
      currentCluster = BPB_RootClus;
    } else {
      currentCluster = parentCluster;
    }
    return;
  }

  uint32_t cluster;
  char *dirname;
  
  if (token[1][0] == '/') {  // Absolute path
      cluster = BPB_RootClus;
      dirname = token[1] + 1;
  } else {  // Relative path
      if (currentCluster == 0) {
          cluster = BPB_RootClus;
      } else {
          cluster = currentCluster;
      }
      dirname = token[1];
  }

  int found = 0;
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);
    
    for (int i = 0; i < 16; i++) {
      if (dir[i].DIR_Name[0] == 0x00) {
        break;
      }
      if ((uint8_t)dir[i].DIR_Name[0] == 0xE5) {
        continue;
      }
      if (!(dir[i].DIR_Attr & 0x10)) {
        continue;
      }

      if (compare(dirname, dir[i].DIR_Name)) {
        found = 1;
        currentCluster = dir[i].DIR_FirstClusterLow;
        break;
      }
    }
    
    if (found) {
      break;
    }
    cluster = NextLB(cluster);
  }

  if (!found) {
    printf("Error: Directory not found\n");
  }
}

void readImg(char *token[]){
  if (token[1] == NULL || token[2] == NULL || token[3] == NULL) {
    printf("Error: Invalid command usage\n");
    return;
  }

  int position = atoi(token[2]);
  int num_bytes = atoi(token[3]);

  //optional input, default hex (= 0)
  int output_type = 0;
  if (token[4] != NULL) {
    if (strcmp(token[4], "-ascii") == 0) {
      output_type = 1;
    } else if (strcmp(token[4], "-dec") == 0) {
      output_type = 2;
    }
  }

  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  int found = 0;
  struct DirectoryEntry fileEntry;
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {
      if (dir[i].DIR_Name[0] == 0x00 || (uint8_t)dir[i].DIR_Name[0] == 0xE5) {
        continue;
      }

      if (compare(token[1], dir[i].DIR_Name)) {
        found = 1;
        fileEntry = dir[i];
        break;
      }
    }
    
    if (found) break;
    cluster = NextLB(cluster);
  }

  if (!found) {
    printf("Error: File not found\n");
    return;
  }

  cluster = fileEntry.DIR_FirstClusterLow;
  int bytes_per_cluster = BPB_BytesPerSec * BPB_SecPerClus;
  //<position> starting point/cluster  of file
  int clusters_to_skip = position / bytes_per_cluster;
  int offset_in_cluster = position % bytes_per_cluster;


  for (int i = 0; i < clusters_to_skip && cluster < 0x0FFFFFF8; i++) {
    cluster = NextLB(cluster);
  }
  if (cluster >= 0x0FFFFFF8) {
    printf("Error: Failed to read file\n");
    return;
  }

  // size of output of reading
  uint8_t buffer[num_bytes];
  uint32_t cluster_offset = LBAToOffset(cluster);
  fseek(fp, cluster_offset + offset_in_cluster, SEEK_SET);
  fread(buffer, 1, num_bytes, fp);

  //read until <num_bytes>
  for (int i = 0; i < num_bytes; i++) {
    switch(output_type) {
      case 0:  // hex
        printf("0x%02X ", buffer[i]);
        break;
      case 1:  // ascii
        printf("%c", buffer[i]);
        break;
      case 2:  // decimal
        printf("%d ", buffer[i]);
        break;
    }
  }
  printf("\n");
}

void getImg(char *token[]) {
  if (token[1] == NULL) {
    printf("Error: No filename specified\n");
    return;
  }

  //second input, copy filename
  char *outputFile;
  if (token[2] != NULL) {
    outputFile = token[2];
  } else {
    outputFile = token[1];
  }

  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  //search for file
  int found = 0;
  struct DirectoryEntry fileEntry;
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {
      if (dir[i].DIR_Name[0] == 0x00 || (uint8_t)dir[i].DIR_Name[0] == 0xE5) {
          continue;
      }

      if (dir[i].DIR_Attr & 0x10) {
        continue;
      }

      if (compare(token[1], dir[i].DIR_Name)) {
        found = 1;
        fileEntry = dir[i];
        break;
      }
    }
    
    if (found) break;
    cluster = NextLB(cluster);
  }

  if (!found) {
    printf("Error: File not found\n");
    return;
  }

  //token copy of file or create new file
  FILE *outputfp = fopen(outputFile, "wb");

  //start at cluster of file
  cluster = fileEntry.DIR_FirstClusterLow;
  //total bytes to copy
  uint32_t bytesLeft = fileEntry.DIR_FileSize;
  uint32_t bytes_per_cluster = BPB_BytesPerSec * BPB_SecPerClus;
  uint8_t *buffer = malloc(bytes_per_cluster);

  //read cluster until end of file
  while (cluster < 0x0FFFFFF8 && bytesLeft > 0) {
    uint32_t clusterOffset = LBAToOffset(cluster);
    uint32_t bytes_to_read;
    
    if (bytesLeft < bytes_per_cluster) {
      bytes_to_read = bytesLeft;
    } else {
      bytes_to_read = bytes_per_cluster;
    }

    fseek(fp, clusterOffset, SEEK_SET);
    fread(buffer, 1, bytes_to_read, fp);
    fwrite(buffer, 1, bytes_to_read, outputfp);

    //update bytes left and next cluster
    bytesLeft -= bytes_to_read;
    cluster = NextLB(cluster);
  }

  free(buffer);
  fclose(outputfp);
}


void putImg(char *token[]) {
  if (token[1] == NULL) {
    printf("Error: No filename specified\n");
    return;
  }

  FILE *inputfp = fopen(token[1], "rb");
  if (!inputfp) {
    printf("Error: File not found\n");
    return;
  }

  //To get file size
  fseek(inputfp, 0, SEEK_END);
  uint32_t fileSize = ftell(inputfp);
  fseek(inputfp, 0, SEEK_SET);

  //fat format
  char fatFile[12];
  memset(fatFile, ' ', 11);
  fatFile[11] = '\0';

  //second input, copy filename
  char *inputName;
  if (token[2] != NULL) {
    inputName = token[2];
  } else {
    inputName = token[1];
  }

  char *dot = strchr(inputName, '.');

  //if extension
  if (dot != NULL) {

    //for name part 8 chars space
    int nameLen = dot - inputName;
    if (nameLen > 8) nameLen = 8;
    memcpy(fatFile, inputName, nameLen);

    //for extension part 3 chars space
    char *ext = dot + 1;
    int extendedLen = strlen(ext);
    if (extendedLen > 3) extendedLen = 3;
    memcpy(fatFile + 8, ext, extendedLen);
  } else {
    //if no extension
    int nameLen = strlen(inputName);
    if (nameLen > 8) nameLen = 8;
    memcpy(fatFile, inputName, nameLen);
  }
  
  //Upper case for FAT format
  for (int i = 0; i < 11; i++) {
    fatFile[i] = toupper(fatFile[i]);
  }

  
  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  //search for existing file and free entry
  int found = 0;
  int freeEntry = -1;
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {

      //check if in use
      if (dir[i].DIR_Name[0] != 0x00 && dir[i].DIR_Name[0] != 0xE5) {
        if (compare(inputName, dir[i].DIR_Name)) {
          found = 1;
          break;
        }
      } else if (freeEntry == -1 && (dir[i].DIR_Name[0] == 0x00 || 
                dir[i].DIR_Name[0] == 0xE5)) {
        freeEntry = i;
      }
    }

    if (found || freeEntry != -1) break;

    cluster = NextLB(cluster);
  }

  if (found) {
    printf("Error: File already exists\n");
    fclose(inputfp);
    return;
  }

  //allocate for file data
  uint8_t *buffer = malloc(fileSize);
  fread(buffer, 1, fileSize, inputfp);
  fclose(inputfp);

  //set file properties name, archive, size, cluster
  memset(&dir[freeEntry], 0, sizeof(struct DirectoryEntry));
  memcpy(dir[freeEntry].DIR_Name, fatFile, 11);
  dir[freeEntry].DIR_Attr = 0x20;
  dir[freeEntry].DIR_FileSize = fileSize;
  dir[freeEntry].DIR_FirstClusterHigh = 0;
  uint32_t newCluster = cluster + 2;
  dir[freeEntry].DIR_FirstClusterLow = newCluster;  

  //write file data
  uint32_t dataOffset = LBAToOffset(newCluster);
  fseek(fp, dataOffset, SEEK_SET);
  fwrite(buffer, 1, fileSize, fp);

  //update directory
  uint32_t dirOffset = LBAToOffset(cluster);
  fseek(fp, dirOffset, SEEK_SET);
  fwrite(dir, sizeof(struct DirectoryEntry), 16, fp);

  //update FAT
  uint32_t fatOffset = (BPB_BytesPerSec * BPB_RsvdSecCnt) + (newCluster * 4);
  // End of cluster write
  uint32_t eoc = 0x0FFFFFFF; 
  fseek(fp, fatOffset, SEEK_SET);
  fwrite(&eoc, 4, 1, fp);

  free(buffer);
}

void delImg(char *token[]) {
  if (token[1] == NULL) {
    printf("Error: No filename specified\n");
    return;
  }

  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  int found = 0;
  int delEntry = -1;
  uint32_t delCluster = 0;

  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {
      if ((uint8_t)dir[i].DIR_Name[0] == 0xE5) {
        continue;
      }

      if (dir[i].DIR_Name[0] == 0x00) {
        continue;
      }
      if (dir[i].DIR_Attr & 0x10) {
        continue;
      }

      if (compare(token[1], dir[i].DIR_Name)) {
        found = 1;
        delEntry = i;
        delCluster = cluster;
        
        break;
      }
    }
    
    if (found) break;
    cluster = NextLB(cluster);
  }

  if (!found) {
    printf("Error: File not found\n");
    return;
  }

  uint8_t delMark = 0xE5;
  uint32_t dirOffset = LBAToOffset(delCluster);
  fseek(fp, dirOffset + (delEntry * sizeof(struct DirectoryEntry)), SEEK_SET);
  fwrite(&delMark, 1, 1, fp);
}

void undelImg(char *token[]) {
 if (token[1] == NULL) {
    printf("Error: No filename specified\n");
    return;
  }

  uint32_t cluster;
  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  int found = 0;
  int undelEntry = -1;
  uint32_t undelCluster = 0;
  struct DirectoryEntry tempEntry;

  // convert input filename to FAT format
  char expanded_name[12];
  memset(expanded_name, ' ', 12);
  char *work_name = strdup(token[1]);
  char *name_token = strtok(work_name, ".");
  strncpy(expanded_name, name_token, strlen(name_token));
  name_token = strtok(NULL, ".");
  if (name_token) {
    strncpy((char*)(expanded_name+8), name_token, strlen(name_token));
  }
  expanded_name[11] = '\0';

  // Convert to uppercase
  for (int i = 0; i < 11; i++) {
    expanded_name[i] = toupper(expanded_name[i]);
  }

  //search for deleted
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);
    
    for (int i = 0; i < 16; i++) {
      // Look at deleted entries (0xE5)
      if ((uint8_t)dir[i].DIR_Name[0] != 0xE5) {
        continue;
      }

      // Compare the rest of the filename (skip first char)
      if (memcmp(expanded_name + 1, dir[i].DIR_Name + 1, 10) == 0) {
        found = 1;
        undelEntry = i;
        undelCluster = cluster;
        tempEntry = dir[i];
        break;
      }
    }
    
    if (found) break;
    cluster = NextLB(cluster);
  }

  free(work_name);

  if (!found) {
    printf("Error: File not found\n");
    return;
  }

  if (currentCluster == 0) {
    cluster = BPB_RootClus;
  } else {
    cluster = currentCluster;
  }

  // Check existing file with same name
  while (cluster < 0x0FFFFFF8) {
    readDirectory(cluster, dir);

    for (int i = 0; i < 16; i++) {
      if ((uint8_t)dir[i].DIR_Name[0] != 0xE5 && dir[i].DIR_Name[0] != 0x00) {
        if (memcmp(expanded_name, dir[i].DIR_Name, 11) == 0) {
          printf("Error: File already exists\n");
          return;
        }
      }
    }
    
    cluster = NextLB(cluster);
  }

  //spot of directory entry for undel
  uint32_t diroffset = LBAToOffset(undelCluster);
  fseek(fp, diroffset + (undelEntry * sizeof(struct DirectoryEntry)), SEEK_SET);
  
  memcpy(tempEntry.DIR_Name, expanded_name, 11);
  // Write directory entry
  fwrite(&tempEntry, sizeof(struct DirectoryEntry), 1, fp);
}



int main( int argc, char * argv[] ){

  char * command_string = (char*) malloc( MAX_COMMAND_SIZE );
  char error_message[30] = "An error has occurred\n";

  while(1){

    // Read the command from the commandi line.  The
    // maximum command that will be read is MAX_COMMAND_SIZE
    // This while command will wait here until the user
    // inputs something.

    //it repeatedly prints a prompt msh> 
    printf ("mfs> ");
    if( !fgets (command_string, MAX_COMMAND_SIZE, stdin) ){
      exit(0);
    }

    for (int i = 0; i < strlen(command_string); i++) {
      command_string[i] = tolower(command_string[i]);
    } 
    
    //for repeated enter keys
    if(strcmp(command_string, "\n") == 0) {
      continue;
    }

    //handles test #15 excessive whitespace
    char *start = command_string;
    while (isspace(*start)) {
      start++;
    }
    if (strlen(start) == 0) {
      continue;
    }

    /* Parse input */
    char *token[MAX_NUM_ARGUMENTS];
    int token_count = 0;  
    // Pointer to point to the token
    // parsed by strsep
    char *argument_pointer;                                
    char *working_string  = strdup( start ); 
    // we are going to move the working_string pointer so
    // keep track of its original value so we can deallocate
    // the correct amount at the end
    char *head_ptr = working_string;
  
    // Tokenize the input with whitespace used as the delimiter
    while ( ( (argument_pointer = strsep(&working_string, WHITESPACE ) ) != NULL) &&
              (token_count<MAX_NUM_ARGUMENTS)){
      token[token_count] = strndup( argument_pointer, MAX_COMMAND_SIZE );
      if( strlen( token[token_count] ) == 0 )
      {
        token[token_count] = NULL;
      }
  
      token_count++;  
    }

    if (strcmp(token[0],"open") == 0) {
      if (fp) {
        printf("Error: File system image already open.\n");  
      }
      else if(token[1] == NULL){
        printf("Error: File system image not found.\n");
      }
      else if(token[1] != NULL){
        openImg(token[1]);
      }
    }
    else if(strcmp(token[0],"close") == 0){
      if(fp){
        closeImg(fp);
      }else{
        printf("Error: File system image not open.\n");
      }

    }
    else if(strcmp(token[0],"exit") == 0 || strcmp(token[0],"quit") == 0){
      if (token[1] != NULL) {
      write(STDERR_FILENO, error_message, strlen(error_message));
      } else {
          exit(0);
      }
    }
    else if (strcmp(token[0],"info") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        infoImg();
      }
    }
    else if (strcmp(token[0],"stat") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else {
        statImg(token);
      }
      
    }
    else if (strcmp(token[0],"ls") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        lsImg();
      }
    } 
    else if (strcmp(token[0],"cd") == 0) { 
     if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        cdImg(token);
      }
    }
    else if (strcmp(token[0],"read") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        readImg(token);
      }
    }
    else if (strcmp(token[0],"get") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        getImg(token);
      }
    }
    else if (strcmp(token[0],"put") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        putImg(token);
      }
    }
    else if (strcmp(token[0],"del") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        delImg(token);
      }
    }
    else if (strcmp(token[0],"undel") == 0) {
      if (fp == NULL) {
        printf("Error: File system image must be opened first.\n");
        continue;
      }else{
        undelImg(token);
      }
    } 
    else {
      printf("Error: Command not found\n");
    } 
    

    free( head_ptr );
  }

  free(command_string);
  return 0;
}