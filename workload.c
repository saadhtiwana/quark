#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main() {
    srand(time(NULL));
    char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@#$%^&*";
    
    printf("\033[1;32m"); // Set color to bright green
    
    while(1) {
        for (int i = 0; i < 160; i++) {
            if (rand() % 10 > 2) {
                printf(" ");
            } else {
                printf("%c", chars[rand() % (sizeof(chars) - 1)]);
            }
        }
        printf("\n");
        usleep(50000); // Sleep 50ms to control speed and CPU usage
    }
    return 0;
}
