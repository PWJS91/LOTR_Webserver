;          ___ . .  _                                                                                             
; "T$$$P"   |  |_| |_                                                                                             
;  :$$$     |  | | |_                                                                                             
;  :$$$                                                      "T$$$$$$$b.                                          
;  :$$$     .g$$$$$p.   T$$$$b.    T$$$$$bp.                   BUG    "Tb      T$b      T$P   .g$P^^T$$  ,gP^^T$$ 
;   $$$    d^"     "^b   $$  "Tb    $$    "Tb    .s^s. :sssp   $$$     :$; T$$P $^b.     $   dP"     `T :$P    `T
;   :$$   dP         Tb  $$   :$;   $$      Tb  d'   `b $      $$$     :$;  $$  $ `Tp    $  d$           Tbp.   
;   :$$  :$;         :$; $$   :$;   $$      :$; T.   .P $^^    $$$    .dP   $$  $   ^b.  $ :$;            "T$$p.  
;   $$$  :$;         :$; $$...dP    $$      :$;  `^s^' .$.     $$$...dP"    $$  $    `Tp $ :$;     "T$$      "T$b 
;   $$$   Tb.       ,dP  $$"""Tb    $$      dP ""$""$" "$"$^^  $$$""T$b     $$  $      ^b$  T$       T$ ;      $$;
;   $$$    Tp._   _,gP   $$   `Tb.  $$    ,dP    $  $...$ $..  $$$   T$b    :$  $       `$   Tb.     :$ T.    ,dP 
;   $$$;    "^$$$$$^"   d$$     `T.d$$$$$P^"     $  $"""$ $"", $$$    T$b  d$$bd$b      d$b   "^TbsssP" 'T$bgd$P  
;   $$$b.____.dP                                 $ .$. .$.$ss,d$$$b.   T$b.                                       
; .d$$$$$$$$$$P
;
;
; -----------------------------------------------------------------------
; |                     "ONE SERVER TO RULE THEM ALL "                  |
; -----------------------------------------------------------------------
;
; A LotR Webserver in Linux x86-64
; Listens on 0.0.0.0:8080 and replies with a random LotR quote.
; Build: nasm -felf64 -g -F dwarf -o lotr_webserver.o lotr_webserver.asm
; Link: ld -o lotr_webserver lotr_webserver.o
; Run: ./lotr_webserver
; Test: 
;       1. curl http://127.0.0.1:8080/ OR nc 127.0.0.1 8080
;       2. for i in {1..10}; do curl -s localhost:8080 >/dev/null & done
;
; Dependencies:
;       quotes.txt -> quotes seperated by "::quotes::" marker
;       art.txt -> ASCII art seperated by "::art::" marker
; Notes: 
;       Some definitions below share the same constants. This is because
;       the Linux kernal interprets these numbers differently depending
;       on which system call parameters receives them.
;
;       Port numbers need to be stored in network byte order, but x86 stores
;       values as little-endian.
;
; References:
;       https://x64.syscall.sh/
;
; Date Created: 23/11/25
; Author: PWStace
; 
; ------------- Syscall/Socket/Constants --------------
%define SYS_read        0
%define SYS_write       1
%define SYS_open        2
%define SYS_close       3
%define SYS_socket      41
%define SYS_accept      43
%define SYS_bind        49
%define SYS_listen      50
%define SYS_setsockopt  54
%define SYS_fork        57
%define SYS_getrandom   318
%define SYS_exit        60
%define SYS_wait4       61

%define AF_INET         2
%define SOCK_STREAM     1
%define SOL_SOCKET      1
%define SO_REUSEADDR    2
%define WNOHANG         1

%define BACKLOG         128

%define CR              13 ;=\r
%define LF              10 ;=\n
%define NUL             0  ;=NUL

; Set relative offsets (i.e. RIP relative addresses) 
default rel

section .data align=8
; ------- HTTP header (includes Content-Length) --------
        header:         db "HTTP/1.0 200 OK", CR, LF, \
                        "Content-Type: text/plain; charset=utf-8", CR, LF, \
                        "Connection: close", CR, LF, \
                        "Cache-Control: no-store", CR, LF, \
                        "Content-Length: "
        header_len:     equ $ - header
        header_end:     db CR, LF, CR, LF
        hdr_end_len:    equ $ - header_end

; -------- HTTP Error codes (just 500 for now) --------
        err_500:        db "HTTP/1.0 500 Internal Server Error", CR, LF, \
                           "Content-Type: text/plain; charset=utf-8", CR, LF, \
                           "Connection: close", CR, LF, \
                           "Content-Length: 22", CR, LF, CR, LF, \
                           "Internal Server Error", LF
        err_500_len:     equ $ - err_500

; --------------- sockaddr_in (16 bytes) --------------
; struct { sa_family=AF_INET (2), sin_port=htons(8080), sin_addr=INADDR_ANY (0), sin_zero[8]=0 }
        addr:
                         dw AF_INET
                         dw 0x901F      ; little-endian to specifiy port 8080 (stores 0x1F90 in big-endian)
                         dd 0
                         dq 0           ; 8 bytes of padding to match size of generic sockaddr struct
        one:             dd 1           ; for SO_REUSEADDR (allows server to reuse a port even if it is in TIME_WAIT)

; ------------------- Path to Wisdom -------------------
        filepath_quotes: db "/home/kali/webserver/quotes.txt", 0
        filepath_art:    db "/home/kali/webserver/art.txt", 0
        sep:             db LF, LF
        sep_len:         equ $ - sep

section .bss align=8
        rand32:          resd 1         ; reserves 1 double word (4 bytes)
        quotes_buffer:   resb 2048      ; reservers 2048 bytes
        quotes_array:    resq 128       ; reservers 128 quadwords
        nquotes:         resd 1
        banner_ptr:      resq 1
        banner_len:      resq 1
        art_buffer:      resb 16384
        art_array:       resq 128
        nart:            resd 1
        cont_len_str:    resb 32
        cont_len_len:    resd 1  

section .text
        global _start

; ------------------- http_500_err ----------------------
; | FUNCTION                                            |
; | IN:  r13d = client fd                               |
; | OUT: 500 response, fd closed                        |
; | Clobbers rax, rdi, rsi, and rdx                     |
; -------------------------------------------------------
http_500_err:
        ; This function is used in the parent process
        ; It assumes r13 will hold the client fd
        ; write(client, err_500, err_500_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel err_500]
        mov rdi, err_500_len
        syscall

        ; close(client);
        mov eax, SYS_close
        mov edi, r13d
        syscall

        ret

; ------------------- u64_to_ASCII ----------------------
; | FUNCTION                                            |
; | IN:         rax = unsigned int                      |
; | OUT:        cont_len_str = ASCII digits             |
; |             cont_len_len = number of digits         |
; | Clobbers rax, rbx, rcx, rdx, rsi, and rdi           |
; -------------------------------------------------------
u64_to_ascii:
        mov rdi, cont_len_str   ; rdi now writes to the buffer
        xor ecx, ecx

.u64_div_loop:                          ; divide by 10 algorithm
        xor edx, edx
        mov rbx, 10
        div rbx                         ; rax/rbx, rax=quotiant, rdx=remainder
        add dl, '0'                     ; '0' is 48 in ASCII code
        mov [rdi], dl
        inc rdi
        inc ecx
        test rax, rax
        jnz .u64_div_loop

        ; Rev digits since they are backwards in the buffer
        mov rsi, cont_len_str
        dec rdi

.u64_rev_loop:
        cmp rsi, rdi
        jge .u64_done
        mov al, [rsi]
        mov bl, [rdi]
        mov [rsi], bl
        mov [rdi], al
        inc rsi
        dec rdi
        jmp .u64_rev_loop

.u64_done:
        mov [cont_len_len], ecx
        ret

; -------------------------------------------------------------------------------
; |                             "And so it begins."                             |
; -------------------------------------------------------------------------------

_start:
        ; int open(const char *path, int flags, mode_t mode);
        mov eax, SYS_open
        lea rdi, [rel filepath_quotes]  ; load effective address of filepath str (relative to rip)
        mov esi, 0                      ; O_RDONLY is given as 0 in fcntl(2)
        xor edx, edx                    ; mode = 0
        syscall
        mov r12d, eax                   ; r12 holds fd

        ; ssize_t read(int fd, void buf[count], size_t count);
        mov eax, SYS_read
        mov edi, r12d
        lea rsi, [rel quotes_buffer]
        mov edx, 2048
        syscall
        mov r13d, eax

        ; int close(int fd);
        mov eax, SYS_close
        mov edi, r12d
        syscall

        ; rbx = base address of quotes_buffer
        ; rcx = total bytes read from file
        ; rdx = scratch register used for terminating previous quote
        ; rdi = current byte index in the buffer (0, 1, 2, 3, …)
        ; rsi = pointer to the current candidate position in the buffer (quotes_buffer + rdi)
        xor eax, eax
        mov [nquotes], eax              ; nquotes = 0
        lea rbx, [rel quotes_buffer]
        mov rcx, r13
        xor rdi, rdi
        mov r15, 9                      ; my marker length is 9 bytes

.parse_quote:
        cmp rdi, rcx
        jae .quotes_done
        lea rsi, [rbx + rdi]            ; rsi = &buffer[rdi]

        cmp byte [rsi],     ':'         ; byte 0
        jne .q_next_char
        cmp byte [rsi+1],   ':'         ; byte 1
        jne .q_next_char
        cmp byte [rsi+2],   'q'         ; byte 2
        jne .q_next_char
        cmp byte [rsi+3],   'u'         ; byte 3
        jne .q_next_char
        cmp byte [rsi+4],   'o'         ; byte 4
        jne .q_next_char
        cmp byte [rsi+5],   't'         ; byte 5
        jne .q_next_char
        cmp byte [rsi+6],   'e'         ; byte 6
        jne .q_next_char
        cmp byte [rsi+7],   ':'         ; byte 7
        jne .q_next_char
        cmp byte [rsi+8],   ':'         ; byte 8
        jne .q_next_char

        ; If not first quote, zero-terminate string
        mov eax, [nquotes]
        test eax, eax
        jz .first_quote
        mov rdx, rdi                    ; rdx holds fisrt ':' in marker
        dec rdx                         ; decrement to end of previous quote str
        mov byte [rbx + rdx], 0         ; null-terminate at the address of last byte

.first_quote:
        ; Compute start of quote text
        ; set rax = pointer to start of quote text and store in array
        lea rax, [rsi + 10]
        mov edx, [nquotes]
        mov [quotes_array + rdx*8], rax ; at index 0, we have a pointer to the quote text
        inc dword [nquotes]             ; nquotes = 1
        add rdi, r15
        inc rdi                         ; skip the newline
        jmp .parse_quote

.q_next_char:
        inc rdi
        jmp .parse_quote

.quotes_done:
        ; Terminate last quote
        mov eax, [nquotes]
        test eax, eax
        jz .shutdown_server             ; if no quotes found server will exit gracefully
        mov rdx, rcx
        dec rdx
        mov byte [rbx + rdx], 0

        ; Process Art file now
        ; int open(const char *path, int flags, mode_t mode)
        mov eax, SYS_open
        lea rdi, [rel filepath_art]
        mov esi, 0
        xor edx, edx
        syscall
        mov r12d, eax

        ; ssize_t read(int fd, void buf[count], size_t count)
        mov eax, SYS_read
        mov edi, r12d
        lea rsi, [rel art_buffer]
        mov edx, 16384
        syscall
        mov r13d, eax

        ; int close(int fd)
        mov eax, SYS_close
        mov edi, r12d
        syscall

        xor eax, eax
        mov [nart], eax                 ; set nart to 0
        lea rbx, [rel art_buffer]
        mov rcx, r13
        xor rdi, rdi
        mov r15, 8                      ; marker length

.parse_art:
        cmp rdi, rcx
        jae .art_done
        lea rsi, [rbx + rdi]            ; rsi = &buffer[rdi]
 
        cmp byte [rsi],     ':'
        jne .a_next_char
        cmp byte [rsi+1],   ':'
        jne .a_next_char
        cmp byte [rsi+2],   'a'
        jne .a_next_char
        cmp byte [rsi+3],   'r'
        jne .a_next_char
        cmp byte [rsi+4],   't'
        jne .a_next_char
        cmp byte [rsi+5],   ':'
        jne .a_next_char
        cmp byte [rsi+6],   ':'
        jne .a_next_char

        ; If not first art piece, zero-terminate string
        mov eax, [nart]
        test eax, eax
        jz .banner
        mov rdx, rdi
        dec rdx
        mov byte [rbx + rdx], 0

.banner:
        lea rax, [rsi + 8]
        mov edx, [nart]
        mov [art_array + rdx*8], rax    ; at index 0, we have a pointer to the ascii art text
        inc dword [nart]                ; nart = 1
        add rdi, r15
        inc rdi
        jmp .parse_art

.a_next_char:
        inc rdi
        jmp .parse_art

.art_done:
        mov eax, [nart]
        test eax, eax
        jz .shutdown_server
        mov rdx, rcx                    ; rcx = bytes_read
        dec rdx
        mov byte [rbx + rdx], 0

        ; set banner_ptr and banner_len
        ; art_array[0] = banner_ptr
        mov rax, [art_array]
        mov [banner_ptr], rax
        mov rdi, rax
        xor rcx, rcx

.len_banner:
        cmp byte [rdi + rcx], 0
        je .banner_len_done
        inc rcx
        jmp .len_banner

.banner_len_done:
        mov [banner_len], rcx

.begin_socket:
        ; int socket(int domain, int type, int protocol);
        ; int socket(AF_INET(EAX=2), SOCK_STREAM(ESI=1), PROTOCOL(EDX=0));
        mov eax, SYS_socket
        mov edi, AF_INET
        mov esi, SOCK_STREAM
        xor edx, edx
        syscall
        mov r12d, eax                   ; r12 holds server socket file descriptor

        ; setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &one, 4);
        mov eax, SYS_setsockopt
        mov edi, r12d
        mov esi, SOL_SOCKET
        mov edx, SO_REUSEADDR
        lea r10, [rel one]
        mov r8d, 4
        syscall

        ; int bind(int sockfd, const stuct sockaddr *addr, socklen_t addrlen);
        ; int bind(sockfd, &addr, 16)
        mov eax, SYS_bind
        mov edi, r12d
        lea rsi, [rel addr]
        mov edx, 16
        syscall

        ; int listen(int sockfd, int backlog);
        mov eax, SYS_listen
        mov edi, r12d
        mov esi, BACKLOG
        syscall

.accept_loop:
        ; int accept4(int sockfd, struct sockaddr *_Nullable restrict addr,
        ;        socklen_t *_Nullable restrict addrlen, int flags);
        ; int accept4(severfd, NULL, NULL);
        mov eax, SYS_accept
        mov edi, r12d
        xor esi, esi
        xor edx, edx
        syscall
        mov r13d, eax                   ; r13 holds client fd

        ; Error check
        test eax, eax
        js .accept_error                ; Check SF value and jmp to .accept_error if < 1

        ; pid_t fork(void);
        mov eax, SYS_fork
        syscall
        test eax, eax
        js .fork_fail                   ; if SF=1 (implies error since eax<1)
        jz .child_proc                  ; if ZF=1 (eax=0)

.parent_proc:
        ; int close(int fd);
        mov eax, SYS_close
        mov edi, r13d
        syscall

.reap_child:
        ; pid_t wait4(pid_t pid, int *_Nullable wstatus, int options,
        ;           struct rusage *_Nullable rusage);
        ; wait4(-1, NUL, WNOHANG, NULL)
        mov eax, SYS_wait4
        mov edi, -1
        xor esi, esi
        mov edx, WNOHANG                ; don't block if no dead children
        xor r10d, r10d
        syscall

        cmp eax, 0
        ; eax > 0 -> successfully reaped a child
        ; eax = 0 -> no more dead children
        ; eax < 0 -> error (can be ignored)
        jg .reap_child
        jmp .accept_loop

.accept_error:
        jmp .accept_loop

.fork_fail: 
        ; fork failed so send 500 code
        ; int close(int fd);
        call http_500_err
        jmp .accept_loop

.child_proc:

        ; int close(int fd);
        mov eax, SYS_close
        mov edi, r12d
        syscall

        ; getrandom(void *buf, size_t buflen, unsigned int flags)
        ; getrandom(&rand32, 4, 0)
        mov eax, SYS_getrandom
        lea rdi, [rel rand32]
        mov esi, 4
        xor edx, edx
        syscall                         ; [rand32] now contains a random 32-bit int

        ; Turn the random number into an index (idx = rand32 % nquotes)
        mov eax, [rand32]
        xor edx, edx
        mov ecx, [nquotes]
        div ecx
        mov esi, edx

        ; r14 = pointer to quote
        lea rbx, [rel quotes_array]
        mov r14, [rbx + rsi*8]

        ; Compute string length
        ; r15 = strlen(quote)
        mov rdi, r14
        xor r15, r15

.len_loop:
        cmp byte [r14 + r15], 0
        je .art_pick
        inc r15
        jmp .len_loop

.art_pick:
        mov eax, [rand32]
        xor edx, edx
        mov ecx, [nart]
        dec ecx                         ; nart - 1 since exluding banner
        div ecx                         ; EAX/ECX (EDX is the remainder)
        mov esi, edx                    ; index range is 0..(nart-2)
        inc esi                         ; skip 0 index to exclude banner; index range is 1..(1-nart)
        lea rbx, [rel art_array]
        mov r8, [rbx + rsi*8]           ; pointer to start of chosen art piece

        ; Compute length of art string
        mov rdi, r8
        xor r9, r9

.len_art_loop:
        ; r8 = pointer to start of string
        ; r9 = index offset
        ; [r8 + r9] = char at pos r9
        cmp byte [r8 + r9], 0           ; use zero-byte inserted during parsing for comparison
        je .done
        inc r9
        jmp .len_art_loop

.done:
        ; Summary of data held: 
        ;       r14             -> pointer to quote
        ;       r15             -> length of quote
        ;       r8              -> pointer to art
        ;       r9              -> length of art
        ;       [banner_ptr]    -> pointer to banner
        ;       [banner_len]    -> length of banner
        ;       sep_len         -> length of LFLF

        ; Compute Content-Length
        ; Content-Length = banner_len + art+len + quote_len + sep_len * 3
        mov rax, [banner_len]
        add rax, r9
        add rax, r15
        add rax, sep_len
        add rax, sep_len
        add rax, sep_len
        call u64_to_ascii

        ; ssize_t write(int fd, const void buf[.count], size_t count);
        ; write(client, header, header_len)
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel header]
        mov edx, header_len
        syscall

        ; write(client, cont_len_str, cont_len_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel cont_len_str]
        mov edx, [cont_len_len]
        syscall

        ; write(client, header_end, hdr_end_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel header_end]
        mov edx, hdr_end_len
        syscall

        ; write(client, sep, sep_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel sep]
        mov edx, sep_len
        syscall

        ; write(client, banner_ptr, banner_len);
        mov eax, SYS_write
        mov edi, r13d
        mov rsi, [banner_ptr]
        mov rdx, [banner_len]
        syscall

        ; write(client, sep, sep_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel sep]
        mov edx, sep_len
        syscall

        ; write(client, art_ptr, art_len);
        mov eax, SYS_write
        mov edi, r13d
        mov rsi, r8
        mov rdx, r9
        syscall

        ; write(client, sep, sep_len);
        mov eax, SYS_write
        mov edi, r13d
        lea rsi, [rel sep]
        mov edx, sep_len
        syscall

        ; write(client, quote, r15);
        mov eax, SYS_write
        mov edi, r13d
        mov rsi, r14
        mov rdx, r15
        syscall

        ; int close(int fd);
        mov eax, SYS_close
        mov edi, r13d
        syscall

        ; [[noreturn]] void exit(int status);
        mov eax, SYS_exit
        xor edi, edi
        syscall

.shutdown_server:
        mov eax, SYS_exit
        xor rdi, rdi
        syscall

;        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣶⣶⣶⣶⣄⠀⢠⣄⡀⠀⠀⠀⠀  "One Ring to rule them all
;        ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⡿⠛⢻⣿⣿⣿⠀⢀⣿⣿⣦⡀⠀⠀   One Ring to find them
;        ⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⠋⠉⠁⠀⣸⣿⣿⡏⠀⢸⣿⣿⣿⣷⡄⠀   One Ring to bring them all
;        ⠀⠀⠀⠀⢀⣾⣿⣿⠋⠁⠉⠀⣰⣶⣾⣿⡿⠟⠀⢠⣿⣿⣿⣿⣿⣿⡄   And in the darkness bind them"
;        ⠀⠀⠀⣴⣿⣿⠟⠛⠀⠀⣿⣿⣿⡿⠛⠉⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⡇
;        ⠀⢀⣾⣿⣿⠿⠀⠀⣶⣾⣿⡿⠋⠀⠀⠀⠀⣰⣿⣿⡟⠉⢻⣿⣿⣿⠇
;        ⠀⣾⣿⡏⠀⢀⣀⣴⣿⡿⠋⠀⠀⠀⠀⣠⣾⣿⣿⠋⠁⠀⢀⣿⣿⡟⠀
;        ⢸⣿⣿⣧⣀⣼⣿⣿⡟⠁⠀⠀⠀⣠⣾⣿⣿⠛⠛⠀⠀⣾⣿⣿⡟⠀⠀
;        ⠸⣿⣿⣿⣿⣿⡿⠏⠀⠀⢀⣠⣾⣿⡿⠿⠿⠀⢠⣤⣾⣿⣿⠟⠀⠀⠀
;        ⠀⠈⠉⠉⠁⠀⢀⣀⣤⣾⣿⣿⠿⠿⠃⠀⣀⣠⣾⣿⣿⡿⠃⠀⠀⠀⠀
;        ⠀⠳⣶⣶⣶⣿⣿⣿⣿⣿⣿⣏⠀⢀⣀⣠⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
;        ⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀
;        ⠀⠀⠀⠀⠙⠻⢿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
;        ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
