/*
* Copyright (c) 2021 ACOAUTO Team.
* All rights reserved.
*
* Detailed license information can be found in the LICENSE file.
*
* File: iotpi_led_jstruct.h iotpi_led JSON <-> C struct.
*
* Date: Tue Mar 01 2022 16:08:02 GMT+0800 (GMT+08:00)
*
* This file is automatically generated by the jstruct tool, please do not modify.
*
* Author: Han.hui <hanhui@acoinfo.com>
*
*/

#ifndef IOTPI_LED_JSTRUCT_H
#define IOTPI_LED_JSTRUCT_H

#include <stdint.h>
#include <stdbool.h>

#ifndef STRUCT_LED_DEFINED
#define STRUCT_LED_DEFINED
struct led {
	bool led1;
	bool led2;
	bool led3;
	void *json;
};
#endif /* STRUCT_LED_DEFINED */

#ifdef __cplusplus
extern "C" {
#endif

/* Deserialize the JSON string into a structure 'led' */
bool iotpi_led_json_parse(struct led *, const char *, size_t);

/* Free iotpi_led_json_parse() buffer, Warning: string type member can no longer be used */
void iotpi_led_json_parse_free(struct led *);

/* Serialize the structure 'led' into a JSON string */
char *iotpi_led_json_stringify(struct led *);

/* Free iotpi_led_json_stringify() return value */
void iotpi_led_json_stringify_free(char *);

#ifdef __cplusplus
}
#endif

#endif /* IOTPI_LED_JSTRUCT_H */
/*
 * end
 */