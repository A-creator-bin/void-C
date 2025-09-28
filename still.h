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
// ------------------- CAMADA 1: QUALIDADE DE VIDA -------------------

// comprimento de string
num strlen(const str *s) {
    num len = 0;
    while (s[len] != '\0') len++;
    ret len;
}

// concatena duas strings (dest precisa ter espaço suficiente)
void strcat(str *dest, const str *src) {
    num i = 0, j = 0;
    while (dest[i] != '\0') i++;
    while ((dest[i++] = src[j++]) != '\0');
}

// compara duas strings (0 se iguais, diferente se não)
num strcmp(const str *a, const str *b) {
    while (*a && (*a == *b)) {
        a++; b++;
    }
    ret *(const unsigned char*)a - *(const unsigned char*)b;
}

// leitura de linha simples (até \n ou tamanho-1)
num inputln(str *buffer, size_t tamanho) {
    ssize_t n = read(0, buffer, tamanho - 1);
    if (n <= 0) ret -1;
    // cortar no \n se houver
    for (ssize_t i = 0; i < n; i++) {
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            ret i;
        }
    }
    buffer[n] = '\0';
    ret n;
}

// mini assert
#define check(cond, msg) \
    do { if (!(cond)) { errors(msg); end(1); } } while (0)

// formatador simples: só suporta %d, %s, %c


// ------------------- CAMADA 2: ESTRUTURAS E MATEMÁTICA -------------------

// ARRAY DINÂMICO SIMPLES
construction Vec {
    num *data;
    num size;
    num capacity;
};

// inicializa vetor
void vec_init(construction Vec *v, num cap) {
    v->data = (num*) alloc(sizeof(num) * cap);
    v->size = 0;
    v->capacity = cap;
}

// adiciona elemento
void vec_push(construction Vec *v, num val) {
    if (v->size >= v->capacity) {
        num new_cap = v->capacity * 2;
        num *new_data = (num*) alloc(sizeof(num) * new_cap);
        for (num i = 0; i < v->size; i++) new_data[i] = v->data[i];
        garbage(v->data, sizeof(num) * v->capacity);
        v->data = new_data;
        v->capacity = new_cap;
    }
    v->data[v->size++] = val;
}

// libera vetor
void vec_free(construction Vec *v) {
    garbage(v->data, sizeof(num) * v->capacity);
    v->data = NULL;
    v->size = 0;
    v->capacity = 0;
}

// FUNÇÕES MATEMÁTICAS BÁSICAS
Mfloat sinf(Mfloat x) { ret sin(x); }
Mfloat cosf(Mfloat x) { ret cos(x); }
Mfloat sqrtf(Mfloat x) { ret sqrt(x); }
Mfloat powf(Mfloat x, Mfloat y) { ret pow(x,y); }
num abs(num x) { ret x < 0 ? -x : x; }

// CONVERSÕES
num str_num(const str *s) {
    num result = 0, sign = 1, i = 0;
    if (s[0] == '-') { sign = -1; i++; }
    for (; s[i]; i++) result = result * 10 + (s[i] - '0');
    ret sign * result;
}

void num_str(num n, str *buf) {
    num i = 0, neg = 0;
    if (n == 0) { buf[i++] = '0'; buf[i] = '\0'; ret; }
    if (n < 0) { neg = 1; n = -n; }
    char tmp[32]; num j = 0;
    while (n > 0) { tmp[j++] = '0' + (n % 10); n /= 10; }
    if (neg) buf[i++] = '-';
    while (j--) buf[i++] = tmp[j];
    buf[i] = '\0';
}

// ------------------- CAMADA 3: SISTEMA -------------------

// leitura de arquivo inteiro em buffer (text ou binário)
num file_read(const str *nome, void *buffer, size_t tamanho) {
    int fd = open(nome, O_RDONLY);
    if (fd < 0) ret -1;
    ssize_t n = read(fd, buffer, tamanho);
    close(fd);
    ret n;  // retorna bytes lidos ou -1
}

// escrever arquivo (sobrescreve se existir)
void file_write(const str *nome, const void *buffer, size_t tamanho) {
    int fd = open(nome, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, buffer, tamanho);
        close(fd);
    } else errors("falha ao abrir arquivo");
}

// append em arquivo
void file_append(const str *nome, const void *buffer, size_t tamanho) {
    int fd = open(nome, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buffer, tamanho);
        close(fd);
    } else errors("falha ao abrir arquivo para append");
}

// variáveis de ambiente
str *getenv_still(const str *var) {
    ret getenv(var);  // retorna ponteiro ou NULL
}

num setenv_still(const str *var, const str *val, num overwrite) {
    ret setenv(var, val, overwrite);
}

// execução de comando shell
num system_still(const str *cmd) {
    ret bash(cmd); // já existe no still.h
}

// simples delay de CPU
void sleep_sec(num s) { sleeping(s*1000); }

// LEITURA BINÁRIA DE ARQUIVO EM VETOR
construction BinFile {
    void *data;
    size_t size;
};
typedef struct BinFile BinFile;


BinFile read_bin(const str *nome) {
    BinFile f = {NULL,0};
    int fd = open(nome, O_RDONLY);
    if (fd < 0) ret f;
    struct stat st;
    if (fstat(fd, &st) == 0) {
        f.size = st.st_size;
        f.data = alloc(f.size);
        read(fd, f.data, f.size);
    }
    close(fd);
    ret f;
}

void free_bin(BinFile *f) {
    if (f->data) garbage(f->data, f->size);
    f->data = NULL;
    f->size = 0;
}

// ------------------- CAMADA 4: ERGONOMIA -------------------

// ifnot(cond) → if (!(cond))


// dump simples de vetor de nums
void dump_vec(construction Vec *v, const str *name) {
    output("[DUMP] ");
    output(name);
    output(": ");
    for(num i=0;i<v->size;i++){
        char buf[32];
        num_to_str(v->data[i], buf);
        output(buf);
        output(" ");
    }
    output("\n");
}

// dump de string
void dump_str(const str *s, const str *name){
    output("[DUMP] ");
    output(name);
    output(": ");
    output(s);
    output("\n");
}

// debug geral: imprime label + valor num
void dump_num(num n, const str *label){
    output("[DUMP] ");
    output(label);
    output(": ");
    char buf[32];
    num_to_str(n, buf);
    output(buf);
    output("\n");
}


#endif //still_h
