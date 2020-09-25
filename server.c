/* server.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <errno.h>
#include <ctype.h>
#include "base64.h"
#include "sha1.h"
#include "server.h"

#define REQUEST_LEN_MAX 1024
#define DEFEULT_SERVER_PORT 8000
#define WEB_SOCKET_KEY_LEN_MAX 256
#define RESPONSE_HEADER_LEN_MAX 1024
#define LINE_MAX 256
#define DEBUG

int epfd,msgid;

int main(int argc, char *argv[])
{
	struct sockaddr_in servaddr;
	int listenfd;
	int port= DEFEULT_SERVER_PORT;
	struct epoll_event ep_event;
	
	if(argc>1){
	    port=atoi(argv[1]);
	}
	if(port<=0||port>0xFFFF){
	    printf("Port(%d) is out of range(1-%d)\n",port,0xFFFF);
	    return -1;
	 }
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	int one =1;
	setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);
    
	if( bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))!=0 ){ //判断bind绑定是否成功
		printf("bind failed \n");
		return -1;
        }
	if( listen(listenfd,20)!=0 ){ //开始监听套接字，已连接队列设置为最大20
		printf("listen failed \n");
		return -1;
        }
	
	epfd=epoll_create(65535); //创建一个epoll 设置epoll的最大描述符数量是65535
	
	key_t key = ftok(".",0);
	msgid = msgget(key,IPC_CREAT|0666);
	
	pthread_t tid[3];
	pthread_create(&tid[0],NULL,recvThread,NULL);
	pthread_detach(tid[0]); 
  	pthread_create(&tid[1],NULL,sendThread,NULL);
	pthread_detach(tid[1]);  
    	pthread_create(&tid[2],NULL,client_service,NULL);
	pthread_detach(tid[2]);
	 
	printf("Listen %d\nAccepting connections ...\n",port);

	while(1){
			//接收客户端请求
			struct sockaddr_in clnt_addr;
			socklen_t clnt_addr_size = sizeof(clnt_addr);
			int clnt_sock = accept(listenfd, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
		if(clnt_sock>0){ //有客户端连接进来
			WebSocketState *state = (WebSocketState*)malloc(sizeof(WebSocketState));
			memset(state,0,sizeof(state));
			state->fd = clnt_sock;
			state->connect=0;
			ep_event.data.ptr = state;
			ep_event.events=EPOLLIN|EPOLLET;
			epoll_ctl(epfd,EPOLL_CTL_ADD,clnt_sock,&ep_event);
			printf("client %s:%hu link\n",inet_ntoa(clnt_addr.sin_addr),clnt_addr.sin_port);
       		 }
			
	
	}
	
}



//负责监听客户端的读事件
void* client_service(void *arg){
	char recvbuf[1024];
	struct epoll_event ep_events[1024];
	while(1){
        int nfds = epoll_wait(epfd,ep_events,1024,-1);
        for(int i=0;i<nfds;i++){ //遍历就绪的描述符
			//判断是否已经建立了连接
			WebSocketState *state = ep_events[i].data.ptr;
		 	if(state->connect==0){
				printf("send shakehand\n");
				//未建立连接
				int n=recv(state->fd,recvbuf,1024,0);//读取该描述符的数据
				if( n <= 0 ){
					close(state->fd); //关闭该描述符
					free(state);
					continue;
				}
				char *secWebSocketKey;
				secWebSocketKey=computeAcceptKey(recvbuf);	 //计算最终的握手值
				if(secWebSocketKey==NULL){
					close(state->fd);
					free(state);
					continue;
				}
				shakeHand(state->fd,secWebSocketKey);   //发送握手包
				free(secWebSocketKey);
				state->connect=1;
				
			}else{
		
				struct mymesg msg;
				msg.mtype=1;
				msg.state = state;
				msgsnd(msgid,&msg,sizeof(WebSocketState*),0);
			} 

         }
      }
	
}


char * fetchSecKey(const char * buf)
{
  char *key;
  char *keyBegin;
  char *flag="Sec-WebSocket-Key: ";
  int i=0, bufLen=0;

  key=(char *)malloc(WEB_SOCKET_KEY_LEN_MAX);//分配握手KEY
  memset(key,0, WEB_SOCKET_KEY_LEN_MAX);
  
  if(!buf){
      return NULL;
    }
 
  keyBegin=strstr(buf,flag); //取得握手数据所在位置
  if(!keyBegin){
      return NULL;
    }
	
  keyBegin+=strlen(flag); //移动指针到握手数据

  bufLen=strlen(buf); //整个握手包的长度
  
  for(i=0;i<bufLen;i++){ //遍历不可超出该长度
      if(keyBegin[i]==0x0A||keyBegin[i]==0x0D)break; //换行符退出

      key[i]=keyBegin[i]; //取得key
  }
  
  return key;
}

char * computeAcceptKey(const char * buf) //计算握手值
{
  char * clientKey;
  char * serverKey; 
  char * sha1DataTemp;
  char * sha1Data;
  short temp;
  int i,n;
  const char * GUID="258EAFA5-E914-47DA-95CA-C5AB0DC85B11"; //标准GUID
 

  if(!buf){
      return NULL;
    }
  clientKey=(char *)malloc(LINE_MAX); //握手长度
  memset(clientKey,0,LINE_MAX);
  
  clientKey=fetchSecKey(buf); //拿出握手的KEY 
 
  if(!clientKey) //拿不到握手KEY
      return NULL;


 
  strcat(clientKey,GUID);//将客户端的KEY和我的GUID进行合并

  sha1DataTemp=sha1_hash(clientKey); //进行sha1摘要
  n=strlen(sha1DataTemp);  //获得摘要长度 是16进制的字符串


  sha1Data=(char *)malloc(n/2+1);  
  memset(sha1Data,0,n/2+1);
 
  for(i=0;i<n;i+=2){      
      sha1Data[i/2]=hex2dec(sha1DataTemp,i,2);    
  } 

  serverKey = base64_encode(sha1Data, strlen(sha1Data)); //base64编码

  return serverKey;
}

void shakeHand(int connfd,const char *serverKey)
{
  char responseHeader [RESPONSE_HEADER_LEN_MAX];

  if(!connfd)return;
  if(!serverKey)return;


  memset(responseHeader,'\0',RESPONSE_HEADER_LEN_MAX);

  sprintf(responseHeader, "HTTP/1.1 101 Switching Protocols\r\n");
  sprintf(responseHeader, "%sUpgrade: websocket\r\n", responseHeader);
  sprintf(responseHeader, "%sConnection: Upgrade\r\n", responseHeader);
  sprintf(responseHeader, "%sSec-WebSocket-Accept: %s\r\n\r\n", responseHeader, serverKey);
 
 // printf("Response Header:%s\n",responseHeader);

  write(connfd,responseHeader,strlen(responseHeader));
}



int recvFrame(WebSocketState* state){
	
	char WebSocketHead[2]; //先读取基础的2字节
	char opcode,RCV,FIN,MASK,l;
	char mask[4];
	//读取数据头部
	int n=recv(state->fd,WebSocketHead,2,0);//读取该描述符的数据
	if(n<2){ 
		return -1;
	}
	opcode = WebSocketHead[0]&0xf;
	FIN = WebSocketHead[0]&0x80;
	RCV = WebSocketHead[0]&0x70;
	MASK = (WebSocketHead[1] & 0x80) == 0x80;
	
	
	l = WebSocketHead[1]&0x7f;
	unsigned long long length=0;
	switch(l){
		case 126:
			n = recv(state->fd,&length,2,0);//读取该描述符的数据
			if(n!=2){
				#ifdef DEBUG
					printf("length read error\n");
				#endif
				return -1;
			}
			break;
		case 127:
			n = recv(state->fd,&length,8,0);//读取该描述符的数据
			if(n!=8){
				#ifdef DEBUG
					printf("length read error\n");
				#endif
				return -1;
			}
			break;
		default:
			length = l;
			break;
	}
	if(MASK){
		n = recv(state->fd,&mask,4,0);
		if(n!=4){
			#ifdef DEBUG
				printf("mask read error\n");
			#endif
			return -1;
		}
	}
	//长度解析完毕
	char *data = (char *)malloc(sizeof(char)*length);
	memset(data,0,sizeof(char)*length);
	if(data == NULL){
		return -1;
	}
	//读取一帧数据
	unsigned long long read=0;
	while(read!=l){
		n=recv(state->fd,data,length,0);//读取该描述符的数据
		if(n<=0){
			#ifdef DEBUG
					printf("data read error\n");
			#endif
			free(data);
			return -1;
		}
		read+=n;
	}
	if(MASK){
		int i;
		for(i=0;i<read;i++){
			data[i] = data[i] ^ mask[i % 4];
		}
		
	}
	WebSocketData* tail=state->WebSocket_recv;
	if(tail==NULL){ //数据头
		//判断OPCODE是否不为0 因为是数据头 OPCODE不可能为0
		if(opcode==0)return -1;
		tail = (WebSocketData*)malloc(sizeof(WebSocketData));
		state->WebSocket_recv = tail;
	}else{
		//寻找WebSocketData链表中的最后一个
		while(tail->next)tail=tail->next;
		if(tail->isall==1){ //重新开一个WebSocketData
			if(opcode==0)return -1; 
			tail->next = malloc(sizeof(WebSocketData));
			tail=tail->next;
			
		}
		
	}
	memset(tail,0,sizeof(WebSocketData));
	tail->type = opcode;
	tail->datalen+=length;
	//创建frame;
	WebSocketFrame * frame = malloc(sizeof(WebSocketFrame));
	memset(frame,0,sizeof(frame));
	frame->datalen = length;
	frame->next =NULL;
	frame->data  = data;

	WebSocketFrame * framep = tail->headframe;
	
	if(framep){
		while(framep->next) framep=framep->next;
		framep->next = frame;
	}else{
		tail->headframe = frame;
	}
	if(FIN){ //代表消息已经接受完毕
		//消息的逻辑处理过程

		char *data = (char *)malloc(sizeof(char)*tail->datalen);
		memset(data,0,tail->datalen);
		WebSocketFrame * headframe = tail->headframe;
		while(headframe){ //将所有帧读取到一个数据里
			memcpy(data,headframe->data,headframe->datalen);
			headframe = headframe->next;
			
		}
		WebSocketSysMsg(state,data,tail->type,frame->datalen);
		state->WebSocket_recv=tail->next;
		cleanWebSocketData(tail);
	}
	return 0;
	
}

int sendFrame(int fd,WebSocketFrame* frame){
	if(frame){
		int headlength=0;
		char *data = (char *)malloc(sizeof(char)*(frame->datalen+10));
		memset(data,0,sizeof(char)*(frame->datalen+10));
		data[0] |= frame->opcode;
		headlength++;
		if(frame->next==NULL)data[0]|=0x80;
		if(frame->datalen<126){
			data[1]= frame->datalen;
			headlength++;
		}else if(frame->datalen==126){
			data[1]=126;
			memcpy(&data[2],&frame->datalen,2);
			headlength+=3;
		}else if(frame->datalen==127){
			data[1]=127;
			memcpy(&data[2],&frame->datalen,8);
			headlength+=9;
		}
		memcpy(data+headlength,frame->data,frame->datalen);
		
		write(fd,data,frame->datalen+headlength);
	}
	return 0;
}

int WebSocketSendMsg(WebSocketState* state,char* buf,int length,int opcode){
	int framecount = length/65535;
	if(length%65535)framecount+=1;
	WebSocketData *data = (WebSocketData*)malloc(sizeof(WebSocketData));
	memset(data,0,sizeof(WebSocketData));
	if(state->WebSocket_send==NULL){
		state->WebSocket_send = data;
	}else{
		WebSocketData *tmp = state->WebSocket_send;
		while(tmp->next)tmp=tmp->next;
		tmp->next=data;
	}
	data->headframe = (WebSocketFrame*)malloc(sizeof(WebSocketFrame));
	memset(data->headframe,0,sizeof(WebSocketFrame));
	WebSocketFrame* frametail = data->headframe;
	frametail->opcode = opcode; //首帧要指明数据类型
	while(framecount){
		if(framecount==1){//最后一帧了
			frametail->datalen = length;
		}else{
			frametail->datalen=65535;
			length -= 65535;
		}
		char * data1 = (char*)malloc(sizeof(char)*frametail->datalen);
		memset(data1,0,sizeof(char)*frametail->datalen);
		frametail->data = data1;
		
		memcpy(data1,buf,frametail->datalen);
	
		
		buf+=frametail->datalen;
		framecount--;
		if(framecount){
			WebSocketFrame* newframe = (WebSocketFrame*)malloc(sizeof(WebSocketFrame));
			memset(newframe,0,sizeof(WebSocketFrame));
			frametail->next = newframe;
			frametail = newframe;
		}
		
	}
	state->untreated_Sendframe++; //待发送消息+1

	struct mymesg msg;
	msg.mtype=2;
	msg.state = state;
	msgsnd(msgid,&msg,sizeof(WebSocketState*),0);
}

void cleanWebSocket(WebSocketState* state){
	WebSocketData* data = state->WebSocket_recv;
	while(data){
		WebSocketData* tmp=data;
		data=data->next;
		cleanWebSocketData(tmp);
	}
	data = state->WebSocket_send;
	while(data){
		WebSocketData* tmp=data;
		data=data->next;
		cleanWebSocketData(tmp);
	}
}

void cleanWebSocketData(WebSocketData* data){
	WebSocketFrame* frame = data->headframe;
	while(frame){
		WebSocketFrame* tmp=frame;
		frame=frame->next;
		if(tmp->data)free(tmp->data);
		free(tmp);
	}
	free(data);
}

void* recvThread(void* arg){ //处理接受消息线程
	struct mymesg msg;
	while(1){
		msgrcv(msgid,&msg,sizeof(WebSocketState*),1,0); //消息类型为1的才是接受消息
		WebSocketState* state= msg.state;
		state->untreated_Msgframe--;
		int ret = recvFrame(state);
		
		if(ret==-1){
			state->error=1; //标志错误
			if(state->untreated_Msgframe==0&&state->untreated_Sendframe==0){
				close(state->fd);
				cleanWebSocket(state);
			}
		}
		
	}
}

void* sendThread(void* arg){  //处理发送消息线程
	struct mymesg msg;
	while(1){
		msgrcv(msgid,&msg,sizeof(WebSocketState*),2,0); //消息类型为2的才是发送消息
		WebSocketState* state= msg.state;
		state->untreated_Sendframe--;
		if(state->error==1 && state->untreated_Sendframe==0&& state->untreated_Msgframe==0 ){//如果发生了错误 且没有待发送的数据了
				close(state->fd);
				cleanWebSocket(state);
		}else{
			//找到第一条需发送的数据发送
			WebSocketData* head=state->WebSocket_send;
			state->WebSocket_send = head->next;
			if(head!=NULL){
				int ret = 0;
				WebSocketFrame* frame=head->headframe;
				while(frame){
					ret = sendFrame(state->fd,frame);
					if(ret==-1){
						//发生了错误
						state->error=1;
						if(state->untreated_Sendframe==0&& state->untreated_Msgframe==0 ){//如果发生了错误 且没有待发送的数据了
							close(state->fd);
							cleanWebSocket(state);
							break;
						}
					}
					frame=frame->next;
				}
				if(ret!=-1)cleanWebSocketData(head);
			}
		}
		
	}
}


void WebSocketSysMsg(WebSocketState * state,char* buf,int opcode,int length){
	if(opcode==8){//关闭包
		WebSocketSendMsg(state,buf,length,opcode);
		close(state->fd);
		free(state);
		
	}else if(opcode==1){ //文本消息
		WebSocketSendMsg(state,buf,length,opcode);
	}else if(opcode==9){ //ping
		WebSocketSendMsg(state,buf,length,0xa); //pong
	}else{
		#ifdef DEBUG
			printf("other message\n");
		#endif
	}
	
}



int hex2dec(const char s[],int start,int len) 
{ 
    int i=0,j; 
    int n = 0; 
    i+=start;
    j=0;
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >='A' && s[i] <= 'F');++i) 
    {   
		if(j>=len)break;
		if (tolower(s[i]) > '9') 
			n = 16 * n + (10 + tolower(s[i]) - 'a'); 
		else 
			n = 16 * n + (tolower(s[i]) - '0'); 
		j++;
    } 
    return n; 
} 
