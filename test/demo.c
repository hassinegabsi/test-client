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
    printf("connection success time = %d\n",time(NULL));
  }
}
void disconnection_callback(struct mosquitto* mosq, void *obj, int rc)
{
  if (rc) {
    printf("disconnection 2 error: %d (%s) time = %d\n", rc, mosquitto_connack_string(rc),time(NULL));
    //exit(1);
  }
  else {
    printf("connection 2 success\n");
  }
}

int main(int argc, char *argv[])
{
	struct mosquitto *mosq;
	int i=0;
	size_t total_size = 0;
	uint8_t buf[MESSAGE_SIZE];
	int iRet0;
	char topic[100];
	memset(topic,0,sizeof(topic));
	mosquitto_lib_init();
	snprintf(topic,sizeof(topic)-1,"topic/%d",atoi(argv[1]));
	mosq = mosquitto_new(argv[1], true, NULL);
  	mosquitto_connect_callback_set(mosq, connection_callback);
	mosquitto_disconnect_callback_set(mosq,disconnection_callback);
 	int iRet = mosquitto_username_pw_set(mosq, "client2", "test");
	printf("\n\n iRet = %d\n\n",iRet);

	mosquitto_tls_set(mosq,"ca.crt", NULL,NULL, NULL,NULL);
	mosquitto_will_set(mosq, topic, 19, "offline-no-network", 1, true);
	//mosquitto_publish_callback_set(mosq, my_publish_callback);

	//int iRet1 = mosquitto_connect(mosq, HOST, PORT, 600);
	//printf("\n\n iRet = %d errno =%d\n\n",iRet1,errno);
	//mosquitto_loop_start(mosq);
	  int resultCode = mosquitto_connect(mosq, HOST, PORT, 15);
	  if (resultCode != MOSQ_ERR_SUCCESS) {
	    fprintf(stderr, "error calling mosquitto_connect\n");
	    exit(1);
	  }

	  int loop = mosquitto_loop_start(mosq);
	  if(loop != MOSQ_ERR_SUCCESS || loop == MOSQ_ERR_NO_CONN){
	    fprintf(stderr, "Unable to start loop: %i\n", loop);
	    exit(1);
	  }

	
	int pubRet;
	char pBuffer[9];
	while(1){
		
		//memset(pBuffer,0,sizeof(pBuffer));
		snprintf(pBuffer,sizeof(pBuffer)-1,"msg%d",i);
		total_size = total_size + strlen(pBuffer)+1;
		printf("pBuffer = %s total size = %d topic = %s\n",pBuffer,total_size,topic);
		i = i + 1;
		//if(i==2)
		pubRet = mosquitto_publish(mosq, NULL, topic,strlen(pBuffer)+1, pBuffer, 0,false);
		//printf("pubRet = %d\n");
		if( pubRet == MOSQ_ERR_NO_CONN){
	   		 fprintf(stderr, "error publish================================= time = %d\n ",time(NULL));
		}
		//usleep(100000);
		sleep(1);
		
		/*if(i == 10000){
			// Crude "messages per second" count 
			i = message_count;
			message_count = 0;
			printf("%d\n", i);
			i = 0;
		}*/
	}
	mosquitto_loop_stop(mosq, false);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}

/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/
/*
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "mosquitto_ctrl.h"

static int run = 1;

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	UNUSED(properties);

	if(ctrl->payload_callback){
		ctrl->payload_callback(ctrl, msg->payloadlen, msg->payload);
	}

	mosquitto_disconnect_v5(mosq, 0, NULL);
	run = 0;
}


static void on_publish(struct mosquitto *mosq, void *obj, int mid, int reason_code, const mosquitto_property *properties)
{
	UNUSED(obj);
	UNUSED(mid);
	UNUSED(properties);

	if(reason_code > 127){
		fprintf(stderr, "Publish error: %s\n", mosquitto_reason_string(reason_code));
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


static void on_subscribe(struct mosquitto *mosq, void *obj, int mid, int qos_count, const int *granted_qos, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	UNUSED(mid);
	UNUSED(properties);

	if(qos_count == 1){
		if(granted_qos[0] < 128){
		
			mosquitto_publish(mosq, NULL, ctrl->request_topic, (int)strlen(ctrl->payload), ctrl->payload, ctrl->cfg.qos, 0);
			free(ctrl->request_topic);
			ctrl->request_topic = NULL;
			free(ctrl->payload);
			ctrl->payload = NULL;
		}else{
			if(ctrl->cfg.protocol_version == MQTT_PROTOCOL_V5){
				fprintf(stderr, "Subscribe error: %s\n", mosquitto_reason_string(granted_qos[0]));
			}else{
				fprintf(stderr, "Subscribe error: Subscription refused.\n");
			}
			run = 0;
			mosquitto_disconnect_v5(mosq, 0, NULL);
		}
	}else{
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


static void on_connect(struct mosquitto *mosq, void *obj, int reason_code, int flags, const mosquitto_property *properties)
{
	struct mosq_ctrl *ctrl = obj;

	UNUSED(flags);
	UNUSED(properties);

	if(reason_code == 0){
		if(ctrl->response_topic){
			mosquitto_subscribe(mosq, NULL, ctrl->response_topic, ctrl->cfg.qos);
			free(ctrl->response_topic);
			ctrl->response_topic = NULL;
		}
	}else{
		if(ctrl->cfg.protocol_version == MQTT_PROTOCOL_V5){
			if(reason_code == MQTT_RC_UNSUPPORTED_PROTOCOL_VERSION){
				fprintf(stderr, "Connection error: %s. Try connecting to an MQTT v5 broker, or use MQTT v3.x mode.\n", mosquitto_reason_string(reason_code));
			}else{
				fprintf(stderr, "Connection error: %s\n", mosquitto_reason_string(reason_code));
			}
		}else{
			fprintf(stderr, "Connection error: %s\n", mosquitto_connack_string(reason_code));
		}
		run = 0;
		mosquitto_disconnect_v5(mosq, 0, NULL);
	}
}


int client_request_response(struct mosq_ctrl *ctrl)
{
	struct mosquitto *mosq;
	int rc;
	time_t start;

	if(ctrl->cfg.cafile == NULL && ctrl->cfg.capath == NULL){
		fprintf(stderr, "Warning: You are running mosquitto_ctrl without encryption.\nThis means all of the configuration changes you are making are visible on the network, including passwords.\n\n");
	}

	mosquitto_lib_init();

	mosq = mosquitto_new(ctrl->cfg.id, true, ctrl);
	rc = client_opts_set(mosq, &ctrl->cfg);
	if(rc) goto cleanup;

	mosquitto_connect_v5_callback_set(mosq, on_connect);
	mosquitto_subscribe_v5_callback_set(mosq, on_subscribe);
	mosquitto_publish_v5_callback_set(mosq, on_publish);
	mosquitto_message_v5_callback_set(mosq, on_message);

	rc = client_connect(mosq, &ctrl->cfg);
	if(rc) goto cleanup;

	start = time(NULL);
	while(run && start+10 > time(NULL)){
		mosquitto_loop(mosq, -1, 1);
	}

cleanup:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return rc;
}

*/



