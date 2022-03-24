/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mosquitto.h>
#include<errno.h>

#define HOST "mosquitto.p24video.com"
#define PORT 9001//1883

#define PUB_QOS 1
#define SUB_QOS 1
#define MESSAGE_SIZE 1024L

static int message_count = 0;

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	message_count++;
}
void connection_callback(struct mosquitto* mosq, void *obj, int rc)
{
  if (rc) {
    printf("connection error: %d (%s)\n", rc, mosquitto_connack_string(rc));
    //exit(1);
  }
  else {
    printf("connection success\n");
  }
}
int main(int argc, char *argv[])
{
	struct mosquitto *mosq;
	int i;
	uint8_t buf[MESSAGE_SIZE];

	mosquitto_lib_init();

	mosq = mosquitto_new(NULL, true, NULL);
  	mosquitto_connect_callback_set(mosq, connection_callback);

 	int iRet = mosquitto_username_pw_set(mosq, "client1", "test");
	printf("\n\n iRet = %d\n\n",iRet);
	mosquitto_tls_set(mosq,"ca.crt", NULL,NULL, NULL,NULL);
	mosquitto_publish_callback_set(mosq, my_publish_callback);
	//int iRet1 = mosquitto_connect(mosq, HOST, PORT, 600);
	//printf("\n\n iRet = %d errno =%d\n\n",iRet1,errno);
	//mosquitto_loop_start(mosq);
	  int resultCode = mosquitto_connect(mosq, HOST, PORT, 60);
	  if (resultCode != MOSQ_ERR_SUCCESS) {
	    fprintf(stderr, "error calling mosquitto_connect\n");
	    exit(1);
	  }

	  int loop = mosquitto_loop_start(mosq);
	  if(loop != MOSQ_ERR_SUCCESS){
	    fprintf(stderr, "Unable to start loop: %i\n", loop);
	    exit(1);
	  }
	mosquitto_will_set(mosq, "topic/1", 8, "test===", 0, true);
	i=0;
	while(1){
		mosquitto_publish(mosq, NULL, "topic/1", 5, "msg1", 0, false);
		usleep(100);
		i++;
		if(i == 10000){
			/* Crude "messages per second" count */
			i = message_count;
			message_count = 0;
			printf("%d\n", i);
			i = 0;
		}
	}
	mosquitto_loop_stop(mosq, false);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}

