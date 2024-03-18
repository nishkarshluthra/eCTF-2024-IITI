#include<stdio.h>
#include<stdlib.h>
#include<string.h>
void read_file(char *filename, char *buffer, int len) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("File not found\n");
        return;
    }
    fread(buffer, 1, len, file);
    fclose(file);
}

void write_file(char *filename, char *buffer, int len) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("File not found\n");
        return;
    }
    fwrite(buffer, 1, len, file);
    fclose(file);
}

void find_keyword(char *buffer, char *keyword, int *index){
    *index = -1;
    for (int i = 0; i<strlen(buffer)-strlen(keyword); i++) {
        if (strncmp(buffer+i, keyword, strlen(keyword)) == 0) {
            *index = i;
            return;
        }
    }
}

int test_hash(int pin){
    return pin*pin;
}

char* update_value(char *buffer, char *keyword) {
    char* update_buffer = (char*)malloc(1000*sizeof(char));
    int index;
    int pin = 0;
    find_keyword(buffer, keyword, &index);
    int update_index = 0;
    for (int i = 0; i<index; i++) {
        update_buffer[update_index++] = buffer[i];
    }
    for (int i = index; i<index+strlen(keyword); i++) {
        update_buffer[update_index++] = buffer[i];
    }
    int i = index+strlen(keyword);
    while (buffer[i] == ' ' || buffer[i] == '\t' || buffer[i] == '\n' || buffer[i] == '\r') {
        update_buffer[update_index++] = buffer[i];
        i++;
    }
    while (i<strlen(buffer) && buffer[i] >= '0' && buffer[i] <= '9') {
        pin = pin*10 + buffer[i] - '0';
        i++;
    }
    pin = test_hash(pin);
    while(pin > 0) {
        update_buffer[update_index++] = pin%10 + '0';
        pin = pin/10;
    }
    while (i<strlen(buffer)) {
        update_buffer[update_index++] = buffer[i];
        i++;
    }
    update_buffer[update_index] = '\0';
    return update_buffer;
}

int main() {
    char* buffer = (char*)malloc(1000*sizeof(char));
    read_file("1.h", buffer, 1000);
    printf("%s\n", buffer);
    char *update_buffer = update_value(buffer, "AP_PIN");
    printf("%s\n", update_buffer);
    write_file("1_n1.h", update_buffer, strlen(update_buffer));
    char* update_buffer2 = update_value(update_buffer, "AP_TOKEN");
    printf("%s\n", update_buffer2);
    write_file("1_n2.h", update_buffer2, strlen(update_buffer2));
    // free the memory
    free(buffer);
    free(update_buffer);
    free(update_buffer2);
    return 0;
}