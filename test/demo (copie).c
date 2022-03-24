#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mosquitto.h"

static void mqtt_connected(struct mosquitto *pstMosq, void *pObject, int iResult, int iFlags, const mosquitto_property *pProperties)
{
    printf("mqtt_connected with:%d\n", iResult);
    mosquitto_subscribe_v5(pstMosq, NULL, "my_mosquitto_topic_20201223", 0, 0, NULL);
    printf("subcribe topic:%s\n", "my_mosquitto_topic_20201223");
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

int main()
{
    struct mosquitto* msqt = NULL;
    
    mosquitto_lib_init();
    msqt = mosquitto_new("mosquitto_demo_id", 0, NULL);
    mosquitto_connect_v5_callback_set(msqt, mqtt_connected);
    mosquitto_disconnect_v5_callback_set(msqt, mqtt_disconnected);
    mosquitto_message_v5_callback_set(msqt, mqtt_msg);
mosquitto_tls_set(msqt,
		"ca.crt", NULL,
		NULL, NULL,
		NULL);
    mosquitto_username_pw_set(msqt, "client1", "test");
 mosquitto_will_set(msqt, "topic/1", 20, "test===", 0, true);
    mosquitto_connect_bind_v5(msqt, "mosquitto.ac-video.com", 9001, 30, NULL, NULL);
   mosquitto_publish(msqt, NULL, "topic/1", 20, "mmmmmmm", 0, false);
    mosquitto_loop_forever(msqt, 2000, 1);
    
    mosquitto_destroy(msqt);
    mosquitto_lib_cleanup();

    return 0;
}

