#include "main.h"

void setup()
{
	Serial.begin(115200);
	while(!Serial);   

	for (uint8_t t = 4; t > 0; t--){
		ZERO_LOGD("[+] SETUP BOOT WAIT %d.[%s][%s]\n", t, __DATE__, __TIME__);
		ESP32_DELAY(1500)
	}

	ZERO_LOGD("[+]ESP32_S3 model:%s ", ESP.getChipModel());

	pinMode(LED, OUTPUT);
	digitalWrite(LED, LOW);
	ESP32_DELAY(1500)


	uint8_t thisMenuLevel = 0;
	btn_up.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("UP: keyPress:        %lu ms\n", millis());});
	btn_down.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("DOWN: keyPress:    %lu ms\n", millis());});
	btn_left.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("LEFT: keyPress:    %lu ms\n", millis());});
	btn_right.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("RIGHT: keyPress:  %lu ms\n", millis());});
	btn_a.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("A: keyPress:          %lu ms\n", millis());});
	btn_b.bind(Event_KeyPress, thisMenuLevel, [](){Serial.printf("B: keyPress:          %lu ms\n", millis());});
}

void loop(){
	if(InterruptButton::getMode() != Mode_Asynchronous) InterruptButton::processSyncEvents();
  
	delay(2000);
}