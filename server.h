#ifndef __WEBSOCKET__
#define __WEBSOCKET__

typedef struct WebSocketFrame{
	struct WebSocketFrame* next; //下一个
	int datalen;
	char * data;
	char opcode;
}WebSocketFrame;


typedef struct WebSocketData{
	struct WebSocketData* next; //下一个WebSocketData
	struct WebSocketFrame* headframe; //该WebSocketData内容
	int untreated; //该WebSocketData是否被处理过
	int datalen; //该消息长度
	int isall; //该消息是否完整
	char type; //数据类型
}WebSocketData;

typedef struct webSocketState{
	int fd;  //WebSocket的fd
	int untreated_Msgframe; //未处理的Frame消息
	int untreated_Sendframe; //待发送的消息
	WebSocketData * WebSocket_recv; //接受到的帧
	WebSocketData * WebSocket_send; //待发送的帧
	int error;
	int connect;
}WebSocketState;


struct mymesg{
	long int mtype;	
	WebSocketState* state;
};



void* client_service(void *arg);
char * fetchSecKey(const char * buf);
char * computeAcceptKey(const char * buf);
void shakeHand(int connfd,const char *serverKey);
int WebSocketSendMsg(WebSocketState* state,char* buf,int length,int opcode);
void* sendThread(void* arg);
void* recvThread(void* arg);
void cleanWebSocketData(WebSocketData* data);
void cleanWebSocket(WebSocketState* state);
void WebSocketSysMsg(WebSocketState * state,char* buf,int opcode,int length);
int sendFrame(int fd,WebSocketFrame* frame);
int recvFrame(WebSocketState *state);
int hex2dec(const char s[],int start,int len);


 

#endif