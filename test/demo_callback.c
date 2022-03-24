
/* This provides a crude manner of testing the performance of a broker in messages/s. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mosquitto.h>


#define HOST "mosquitto.ac-video.com"
#define PORT 9001

#define PUB_QOS 1
#define SUB_QOS 1
#define MESSAGE_SIZE 1024L

static int message_count = 0;

void my_publish_callback(struct mosquitto *mosq, void *obj, int mid)
{
	message_count++;
}

static void mqtt_connected(struct mosquitto *pstMosq, void *pObject, int iResult, int iFlags, const mosquitto_property *pProperties)
{
    printf("mqtt_connected with:%d\n", iResult);
    int i;
   // mosquitto_subscribe_v5(pstMosq, NULL, "my_mosquitto_topic_20201223", 0, 0, NULL);
   for(i=0;i<3;i++)
    {
	mosquitto_publish_v5(pstMosq,NULL,"topic/1",20,"message",0,0,NULL);
    }
    printf("publish topic:%s\n", "my_mosquitto_topic_20201223");
}

static void mqtt_disconnected(struct mosquitto *pstMosq, void *pObject, int iReasonCode, const mosquitto_property *pProperties)
{
    printf("mqtt_disconnected with: %d\n", iReasonCode);
    return ;
}

void mqtt_msg(struct mosquitto *msqt, void *pObject, const struct mosquitto_message *msg, const mosquitto_property *pProperties)
{
    printf("Got a message!\n");
    printf("Topic:\n\t%s\n", msg->topic);
    printf("Data length:\n\t%d\n", msg->payloadlen);
    printf("Data:\n\t%s\n\n", (char*)msg->payload);
}


int main(int argc, char *argv[])
{
	struct mosquitto* msqt = NULL;
    	int i;
	mosquitto_lib_init();
	msqt = mosquitto_new("mosquitto_demo_id", 0, NULL);
	mosquitto_connect_v5_callback_set(msqt, mqtt_connected);
	mosquitto_disconnect_v5_callback_set(msqt, mqtt_disconnected);
	mosquitto_message_v5_callback_set(msqt, mqtt_msg);
	mosquitto_tls_set(msqt,"ca.crt", NULL,NULL, NULL,NULL);
	mosquitto_username_pw_set(msqt, "client1", "test");
	mosquitto_will_set(msqt, "topic/1", 20, "desconnected", 0, true);
	//mosquitto_connect_bind_v5(msqt, "mosquitto.ac-video.com", 9001, 30, NULL, NULL);
	mosquitto_connect(msqt, "mosquitto.ac-video.com", 9001, 600);
	//mosquitto_publish(msqt, NULL, "topic/1", 20, "mmmmmmm", 0, false);

	mosquitto_loop_forever(msqt, 2000, 1);

	mosquitto_destroy(msqt);
	mosquitto_lib_cleanup();
/*
	struct mosquitto *mosq;
	int i;
	uint8_t buf[MESSAGE_SIZE];

	mosquitto_lib_init();

	mosq = mosquitto_new("mosquitto_demo_id", 0, NULL);
    	mosquitto_connect_v5_callback_set(mosq, mqtt_connected);
   	mosquitto_disconnect_v5_callback_set(mosq, mqtt_disconnected);
   	 osquitto_message_v5_callback_set(mosq, mqtt_msg);
    	//mosquitto_connect_v5_callback_set(msqt, mqtt_connected);
	//mosquitto_publish_callback_set(mosq, my_publish_callback);
	//mosquitto_connect(mosq, HOST, PORT, 600);
    	mosquitto_connect_bind_v5(mosq, "mosquitto.ac-video.com", 9001, 30, NULL, NULL);
	mosquitto_loop_start(mosq);
	mosquitto_tls_set(mosq,"ca.crt", NULL,NULL, NULL,NULL);
    	mosquitto_username_pw_set(mosq, "client1", "test");
	i=0;
	while(1){
		mosquitto_publish(mosq, NULL, "topic/1", sizeof(buf), buf, PUB_QOS, false);
		usleep(100);
		i++;
		if(i == 10000){
			
			i = message_count;
			message_count = 0;
			printf("%d\n", i);
			i = 0;
		}
	}
	mosquitto_loop_stop(mosq, false);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;*/
return 0;
}

