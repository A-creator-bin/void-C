#ifndef STILL_H
#define STILL_H
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stddef.h>

// no topo do seu arquivo still.h ou em qualquer header C--
#ifdef _STDIO_H
    #error "STILL error:you using stdio,please remove,use still.h"
#endif

#define none void
#define str char
#define num int
#define ret return
#define pause break
#define loop while 
#define Mfloat double
#define float float
#define outside extern
#define construction struct
#define run main

void output(const char *s){
    const char *p = s;
    while(*p) p++;
    size_t len = p - s;
    write(1, s, len);
}
void outputf(const char *msg, Mfloat valor) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s%.3f\n", msg, valor);
    output(buf);
}

void outputhx(const char *msg, int valor) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%s0x%X\n", msg, valor);
    output(buf);
}

void outputp(const char *msg, void *ptr) {
    char buf[32];
    unsigned long addr = (unsigned long)ptr;
    int i = 0;
    buf[i++] = '0';
    buf[i++] = 'x';
    for (int shift = (sizeof(addr)*8)-4; shift >= 0; shift -= 4) {
        int digit = (addr >> shift) & 0xF;
        buf[i++] = digit < 10 ? '0'+digit : 'A'+(digit-10);
    }
    buf[i] = '\0';
    output(msg);
    output(buf);
    output("\n");
}

#include <stdio.h> // apenas para snprintf

void outputn(const char *msg, int valor) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s%d\n", msg, valor);
    output(buf);
}
void outputc(const char *msg, char c) {
    char buf[4] = {0};
    buf[0] = c;
    buf[1] = '\n';
    buf[2] = '\0';
    output(msg);
    output(buf);
}
void outputln() {
    output("\n");
}

void outputb(const char *msg, int b) {
    output(msg);
    if (b)
        output("true\n");
    else
        output("false\n");
}
/* primary function,header C--*/
void header(){
    output("C$$ still.h\n\n");
}

void input(const char *pergunta,char *resposta,size_t tamanho){
    output(pergunta);
    ssize_t n = read(0, resposta, tamanho - 1);
    if(n > 0){
        resposta[n]
         = '\0';
    }
}

char ascii(int n) {
    if (n < 0 || n > 255) return '?'; // valor inválido
    return (char)n;
}


int char_to_utf8(unsigned int codepoint, char *out) {
    if (codepoint <= 0x7F) {
        out[0] = codepoint;
        out[1] = '\0';
        return 1;
    } else if (codepoint <= 0x7FF) {
        out[0] = 0xC0 | (codepoint >> 6);
        out[1] = 0x80 | (codepoint & 0x3F);
        out[2] = '\0';
        return 2;
    } else if (codepoint <= 0xFFFF) {
        out[0] = 0xE0 | (codepoint >> 12);
        out[1] = 0x80 | ((codepoint >> 6) & 0x3F);
        out[2] = 0x80 | (codepoint & 0x3F);
        out[3] = '\0';
        return 3;
    } else if (codepoint <= 0x10FFFF) {
        out[0] = 0xF0 | (codepoint >> 18);
        out[1] = 0x80 | ((codepoint >> 12) & 0x3F);
        out[2] = 0x80 | ((codepoint >> 6) & 0x3F);
        out[3] = 0x80 | (codepoint & 0x3F);
        out[4] = '\0';
        return 4;
    }
    out[0] = '\0';
    return 0; // inválido
}


void file(const char *nome,const char *conteudo){
    int fd = open(nome, O_WRONLY | O_CREAT | O_TRUNC,0644);
    if(fd != -1){
        const char *p = conteudo;
        while(*p) p++;
        write(fd, conteudo,p - conteudo);
        close(fd);
    }
}

void del(const char *nome){
    unlink(nome);
}
void end(int code){
    _exit(code);
}
int bash(const char *cmd) {
    pid_t pid = fork();
    if (pid == 0) {
        // filho
        char *argv[] = {"/bin/sh", "-c", (char*)cmd, NULL};
        execve("/bin/sh", argv, NULL);
        _exit(127); // se execve falhar
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        return status;
    } else {
        return -1; // fork falhou
    }
}

// malloc
void *alloc(size_t size) {
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    return p;
}

// free
void garbage(void *p, size_t size) {
    munmap(p, size);
}
void log(const char *msg){
    output("[LOG] ");
    output(msg);
    output("\n");
}

void warnings(const char *msg){
    output("[WARN] ");
    output(msg);
    output("\n");
}

void errors(const char *msg){
    output("[ERROR] ");
    output(msg);
    output("\n");
}


#include <time.h>  // necessário pra struct timespec

// retorna tempo em milissegundos desde 1970
unsigned long millis() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // CLOCK_MONOTONIC é melhor pra medir intervalos
    return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

// pausa por N milissegundos
void sleeping(unsigned int ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&req, NULL);
}


#endif //still_h